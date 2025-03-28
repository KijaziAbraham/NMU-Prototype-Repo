from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from .models import CustomUser, Prototype, PrototypeAttachment, Department, AuditLog


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    Validates user credentials and authenticates the user.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        user = authenticate(username=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials. Please try again.")

        return {"user": user}


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "email", "username", "role", "department", "phone", "institution_id"]


class DepartmentSerializer(serializers.ModelSerializer):
    """
    Serializer for department details.
    """
    class Meta:
        model = Department
        fields = '__all__'


class PrototypeAttachmentSerializer(serializers.ModelSerializer):
    """
    Serializer for prototype attachments, providing additional metadata.
    """
    filename = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    file_type_display = serializers.CharField(source='get_file_type_display', read_only=True)

    class Meta:
        model = PrototypeAttachment
        fields = [
            'id', 'file_type', 'file_type_display', 'file', 'description',
            'uploaded_at', 'size', 'filename', 'download_url', 'checksum'
        ]
        read_only_fields = ['uploaded_at', 'size', 'filename', 'download_url', 'checksum']

    def get_filename(self, obj):
        return obj.filename

    def get_download_url(self, obj):
        return obj.download_url

    def validate(self, data):
        prototype = data.get('prototype')
        file_type = data.get('file_type')

        if file_type in ['report', 'source']:
            if PrototypeAttachment.objects.filter(prototype=prototype, file_type=file_type).exists():
                raise serializers.ValidationError(
                    f"A {file_type} file already exists for this prototype"
                )
        return data


class PrototypeSerializer(serializers.ModelSerializer):
    """
    Serializer for prototype details, including nested user and department information.
    """
    student = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.filter(role='student')) 
    department = serializers.PrimaryKeyRelatedField(queryset=Department.objects.all())
    reviewer = UserSerializer(read_only=True)
    attachments = PrototypeAttachmentSerializer(many=True, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    supervisor = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.filter(role="staff"))

    class Meta:
        model = Prototype
        fields = '__all__'
        read_only_fields = ['submission_date', 'last_modified', 'reviewer', 'barcode']

    def create(self, validated_data):
        if 'department' not in validated_data:
            raise serializers.ValidationError({"department": "This field is required."})
        return super().create(validated_data)
    
class PrototypeReviewSerializer(serializers.Serializer):
    """
    Serializer for prototype review submission.
    """
    status = serializers.ChoiceField(choices=[
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('needs_revision', 'Needs Revision')
    ])
    feedback = serializers.CharField(required=False)


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for audit logs, tracking user actions.
    """
    user = UserSerializer(read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = '__all__'
