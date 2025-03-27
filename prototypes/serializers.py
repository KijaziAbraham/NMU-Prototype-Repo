from rest_framework import serializers
from .models import Prototype
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import (
    CustomUser, Prototype, 
    PrototypeAttachment, Department,
    AuditLog
)
class LoginSerializer(serializers.Serializer):
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
        fields = ['id', 'username', 'email', 'role']



class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'

class PrototypeAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = PrototypeAttachment
        fields = '__all__'


class PrototypeSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    department = DepartmentSerializer(read_only=True)
    reviewer = UserSerializer(read_only=True)
    attachments = PrototypeAttachmentSerializer(many=True, read_only=True)
    status_display = serializers.CharField(
        source='get_status_display', 
        read_only=True
    )

    class Meta:
        model = Prototype
        fields = '__all__'
        read_only_fields = [
            'submission_date', 'last_modified',
            'reviewer', 'barcode'
        ]



class PrototypeReviewSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=[
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('needs_revision', 'Needs Revision')
    ])
    feedback = serializers.CharField(required=False)

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    action_display = serializers.CharField(
        source='get_action_display',
        read_only=True
    )

    class Meta:
        model = AuditLog
        fields = '__all__'



class PrototypeAttachmentSerializer(serializers.ModelSerializer):
    filename = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    file_type_display = serializers.CharField(source='get_file_type_display', read_only=True)

    class Meta:
        model = PrototypeAttachment
        fields = [
            'id', 'file_type', 'file_type_display', 'file', 
            'description', 'uploaded_at', 'size', 'filename',
            'download_url', 'checksum'
        ]
        read_only_fields = [
            'uploaded_at', 'size', 'filename', 
            'download_url', 'checksum'
        ]

    def get_filename(self, obj):
        return obj.filename

    def get_download_url(self, obj):
        return obj.download_url

    def validate(self, data):
        prototype = data.get('prototype')
        file_type = data.get('file_type')
        
        if file_type in ['report', 'source']:
            if PrototypeAttachment.objects.filter(
                prototype=prototype, 
                file_type=file_type
            ).exists():
                raise serializers.ValidationError(
                    f"A {file_type} file already exists for this prototype"
                )
        return data
    


