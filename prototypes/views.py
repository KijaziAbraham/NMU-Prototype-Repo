from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.db.models import Case, When, Value, IntegerField
from rest_framework import viewsets, permissions, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status
import openpyxl
from django.http import HttpResponse
from weasyprint import HTML
from django.template.loader import render_to_string
from django.contrib.auth import login
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from .permissions import IsPrototypeOwner, IsAdmin, IsStaff, IsStudent, IsOwnerOrReadOnly, IsReviewer
from .serializers import (
    UserSerializer, PrototypeSerializer, PrototypeAttachmentSerializer, 
    DepartmentSerializer, PrototypeReviewSerializer, AuditLogSerializer, LoginSerializer
)
from .models import CustomUser, Prototype, PrototypeAttachment, Department, AuditLog
from .filters import PrototypeFilter
from .services import report_service
import logging
from django.db.models import Q
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ValidationError
from django.http import HttpRequest


logger = logging.getLogger(__name__)

User = get_user_model()


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            login(request, user)
            return Response({
                "message": "Login successful",
                "user": {"id": user.id, "email": user.email, "role": user.role}
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def user_profile(request: HttpRequest) -> Response:
    """
    Handle user profile operations for authenticated users.

    GET: Retrieve the current user's profile details
    PATCH: Update the current user's profile with provided data

    Args:
        request: HTTP request object containing method and data

    Returns:
        Response: JSON response with user data or error message
    """
    user = request.user

    if request.method == "GET":
        # Return user profile data
        profile_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "phone": user.phone,
            "institution_id": user.institution_id,
        }
        return Response(profile_data, status=status.HTTP_200_OK)

    elif request.method == "PATCH":
        try:
            # Update user profile with partial data
            data = request.data
            allowed_fields = {"phone", "email"}

            # Validate input data
            if not data or not any(field in data for field in allowed_fields):
                return Response(
                    {"error": "No valid fields provided for update"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Update only allowed fields
            user.phone = data.get("phone", user.phone)
            user.email = data.get("email", user.email)

            # Validate and save changes
            user.full_clean()  # Runs model validation
            user.save()

            # Prepare response data
            updated_profile = {
                "message": "Profile updated successfully",
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "phone": user.phone,
                "institution_id": user.institution_id,
            }
            return Response(updated_profile, status=status.HTTP_200_OK)

        except ValidationError as e:
            return Response(
                {"error": "Invalid data provided", "details": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    # This should never be reached due to @api_view decorator,
    # but included for completeness
    return Response(
        {"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED
    )


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

        return queryset #admin na staff wanaona project zote
    
    @action(detail=False, methods=['GET'], permission_classes=[IsAuthenticated])
    def all_prototypes(self, request):
        """Return all prototypes for staff & admin."""
        if request.user.role in ['staff', 'admin']:
            prototypes = Prototype.objects.all()
        else:
            return Response({"error": "Unauthorized access."}, status=403)

        serializer = PrototypeSerializer(prototypes, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['POST'])
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


        
    @action(detail=True, methods=['POST'], permission_classes=[IsAuthenticated])
    def review_prototype(self, request, pk=None):
        """Staff can review a specific prototype (only approval allowed)."""
        user = request.user

        if user.role not in ["staff", "admin"]:
            return Response({"error": "Only staff and admins can review prototypes."}, status=403)

        prototype = self.get_object()
        feedback = request.data.get("feedback", "").strip()

        if not feedback:
            return Response({"error": "Feedback is required."}, status=400)

        prototype.status = "submitted_reviewed"  
        prototype.feedback = feedback
        prototype.reviewed_by = user
        prototype.save()

        return Response({"message": "Prototype approved successfully."})
    
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


class PrototypeAttachmentViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing prototype attachments.
    """
    serializer_class = PrototypeAttachmentSerializer
    permission_classes = [IsAuthenticated, IsPrototypeOwner]
    queryset = PrototypeAttachment.objects.all()

    def get_queryset(self):
        """Limit attachments to those owned by the user."""
        return self.queryset.filter(prototype__student=self.request.user).select_related('prototype')

    @action(detail=False, methods=['post'])
    def bulk_create(self, request, prototype_pk=None):
        prototype = get_object_or_404(
            Prototype,
            pk=prototype_pk,
            student=request.user
        )
        
        created_attachments = []
        errors = []
        
        for file in request.FILES.getlist('files'):
            data = {
                'prototype': prototype.id,
                'file_type': request.data.get('file_type', 'other'),
                'file': file,
                'description': request.data.get('description', '')
            }
            serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                created_attachments.append(serializer.data)
            else:
                errors.append({
                    'file': file.name,
                    'errors': serializer.errors
                })

        response_data = {
            'created': created_attachments,
            'errors': errors
        }
        
        status_code = status.HTTP_207_MULTI_STATUS if errors else status.HTTP_201_CREATED
        return Response(response_data, status=status_code)

    def create(self, request, *args, **kwargs):
        request.data._mutable = True
        request.data['prototype'] = kwargs.get('prototype_pk')
        request.data._mutable = False
        return super().create(request, *args, **kwargs)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all()   
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['user', 'action', 'model']
    ordering = ['-timestamp']


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
