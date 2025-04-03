from django.contrib.auth import get_user_model
from django.db.models import Case, When, Value, IntegerField
from rest_framework import viewsets,  filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
import openpyxl
from django.http import HttpResponse
from weasyprint import HTML
from django.template.loader import render_to_string
from .permissions import IsPrototypeOwner, IsAdmin, IsStaff, IsStudent, IsOwnerOrReadOnly, IsReviewer
from .serializers import (
    UserSerializer, PrototypeSerializer, PrototypeAttachmentSerializer, 
    DepartmentSerializer, PrototypeReviewSerializer,  
)
from .models import CustomUser, Prototype, PrototypeAttachment, Department
import logging
from django.db.models import Q
from django.contrib.auth import update_session_auth_hash
logger = logging.getLogger(__name__)
User = get_user_model()
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.parsers import JSONParser


@api_view(["GET", "PATCH"])  
@permission_classes([IsAuthenticated])
def user_profile(request):
    """Return or update logged-in user's details"""
    user = request.user

    if request.method == "GET":
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "phone": user.phone,
            "institution_id": user.institution_id,
        })

    elif request.method == "PATCH":
        data = request.data
        user.phone = data.get("phone", user.phone)  
        user.email = data.get("email", user.email)  
        user.save()

        return Response({
            "message": "Profile updated successfully",
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "phone": user.phone,
            "institution_id": user.institution_id,
        }, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ModelViewSet):
    """View to manage users"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return User.objects.all() if user.role == "admin" else User.objects.filter(id=user.id)

    @action(detail=False, methods=["GET"], permission_classes=[IsAuthenticated])
    def students(self, request):
        """Admin can retrieve all students"""
        if request.user.role != "admin":
            return Response({"error": "Only admins can access this."}, status=403)

        students = User.objects.filter(role="student")
        serializer = self.get_serializer(students, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["GET"], permission_classes=[IsAuthenticated])
    def supervisors(self, request):
        """Retrieve all staff members who act as supervisors"""
        supervisors = User.objects.filter(Q(role="staff") | Q(role="admin"))
        serializer = self.get_serializer(supervisors, many=True)
        return Response(serializer.data)

class PrototypeViewSet(viewsets.ModelViewSet):
    """Manage prototypes and provide role-based filtering"""
    queryset = Prototype.objects.all()
    serializer_class = PrototypeSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'barcode', 'storage_location']
    ordering_fields = ['submission_date']
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        """Ensure students see their own prototypes first"""
        user = self.request.user
        queryset = Prototype.objects.all()

        if user.role == "student":
            return queryset.annotate(
                priority=Case(
                    When(student=user, then=Value(0)), 
                    default=Value(1),
                    output_field=IntegerField(),
                )
            ).order_by("priority", "-submission_date")

        elif user.role == "staff":
            return queryset  

        return queryset         # Admin and staff can see all prototypes

    @action(detail=False, methods=['GET'], permission_classes=[IsAuthenticated])
    def all_prototypes(self, request):
        """Return all prototypes for staff & admin."""
        if request.user.role in ['staff', 'admin']:
            prototypes = Prototype.objects.all()
        else:
            return Response({"error": "Unauthorized access."}, status=403)

        serializer = PrototypeSerializer(prototypes, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['POST'], parser_classes=[JSONParser])
    def assign_storage(self, request, pk=None):
        """Allow admins to assign a storage location"""
        user = request.user
        if user.role != 'admin':
            return Response({"error": "Only admins can assign storage locations."}, status=403)

        prototype = self.get_object()
        storage_location = request.data.get("storage_location", "").strip()

        if not prototype.has_physical_prototype:
            return Response({"error": "This prototype does not have a physical version."}, status=400)

        if not storage_location:
            return Response({"error": "Storage location is required."}, status=400)

        prototype.storage_location = storage_location
        prototype.save()

        # Return the updated prototype object
        serializer = PrototypeSerializer(prototype)
        return Response(serializer.data)


    @action(detail=True, methods=['POST'], permission_classes=[IsAuthenticated], parser_classes=[JSONParser])
    def review_prototype(self, request, pk=None):
        """Staff and Admin can review a specific prototype (approval and feedback)."""
        user = request.user

        # Ensure the user is either staff or admin
        if user.role not in ["staff", "admin"]:
            return Response({"error": "Only staff and admins can review prototypes."}, status=status.HTTP_403_FORBIDDEN)

        # Get the prototype object
        try:
            prototype = self.get_object()
        except Prototype.DoesNotExist:
            return Response({"error": "Prototype not found."}, status=status.HTTP_404_NOT_FOUND)

        # Get and validate feedback data from the request
        feedback = request.data.get("feedback", "").strip()

        if not feedback:
            return Response({"error": "Feedback is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the prototype status is updated correctly (if it's not already reviewed)
        if prototype.status == "submitted_reviewed":
            return Response({"error": "Prototype has already been reviewed."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the prototype with feedback and reviewed status
        prototype.status = "submitted_reviewed"
        prototype.feedback = feedback
        prototype.reviewer = user  # Record the staff/admin who reviewed
        prototype.save()

        return Response({"message": "Prototype reviewed and approved successfully."}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["GET"])
    def storage_locations(self, request):
        """Retrieve all unique storage locations"""
        locations = Prototype.objects.exclude(storage_location__isnull=True).exclude(storage_location="").values_list("storage_location", flat=True).distinct()

        return Response(list(locations))

    @action(detail=False, methods=['GET'])
    def export_excel(self, request):
        """Export prototypes as an Excel file"""
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["ID", "Title", "Barcode", "Storage Location", "Has Physical Prototype"])

        for proto in Prototype.objects.all():
            ws.append([proto.id, proto.title, proto.barcode, proto.storage_location, proto.has_physical_prototype])

        response = HttpResponse(content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = 'attachment; filename="prototypes.xlsx"'
        wb.save(response)
        return response

    @action(detail=False, methods=['GET'])
    def export_pdf(self, request):
        """Export prototypes as a PDF file"""
        prototypes = Prototype.objects.all()
        html_content = render_to_string("export_template.html", {"prototypes": prototypes})
        pdf_file = HTML(string=html_content).write_pdf()

        response = HttpResponse(pdf_file, content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="prototypes.pdf"'
        return response


class DepartmentViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]



@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Allow authenticated users to change their password"""
    user = request.user
    current_password = request.data.get("current_password")
    new_password = request.data.get("new_password")

    if not user.check_password(current_password):
        return Response({"detail": "Current password is incorrect."}, status=400)

    if len(new_password) < 6:
        return Response({"detail": "New password must be at least 6 characters long."}, status=400)

    user.set_password(new_password)
    user.save()

    # Keep the user logged in after password change
    update_session_auth_hash(request, user)

    return Response({"detail": "Password updated successfully!"})

