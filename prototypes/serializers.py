from rest_framework import serializers
from .models import CustomUser, Prototype, PrototypeAttachment, Department


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
    class Meta:
        model = PrototypeAttachment
        fields = ['report', 'source_code']

class PrototypeSerializer(serializers.ModelSerializer):
    attachment = PrototypeAttachmentSerializer(required=True)  # Nested Serializer

    class Meta:
        model = Prototype
        fields = [
            'id', 'student', 'title', 'abstract', 'department',
            'academic_year', 'supervisor', 'submission_date',
            'status', 'has_physical_prototype', 'barcode',
            'storage_location', 'feedback', 'reviewer', 'attachment'
        ]
        read_only_fields = ['id', 'submission_date', 'status', 'barcode']

    def create(self, validated_data):
        """Handle prototype creation along with attachment files"""
        attachment_data = validated_data.pop('attachment')  # Extract attachment data
        prototype = Prototype.objects.create(**validated_data)
        PrototypeAttachment.objects.create(prototype=prototype, **attachment_data)
        return prototype

    def update(self, instance, validated_data):
        """Handle updating prototype along with its attachments"""
        attachment_data = validated_data.pop('attachment', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update attachment if present
        if attachment_data:
            attachment, _ = PrototypeAttachment.objects.get_or_create(prototype=instance)
            for attr, value in attachment_data.items():
                setattr(attachment, attr, value)
            attachment.save()

        return instance
   
  
class PrototypeReviewSerializer(serializers.Serializer):
    """
    Serializer for prototype review submission.
    """
    feedback = serializers.CharField(required=True)
    status = serializers.ChoiceField(choices=[
        ('submitted_not_reviewed', 'Submitted (Not Reviewed)'),
        ('submitted_reviewed', 'Submitted (Reviewed)'),
    ])

    def update(self, instance, validated_data):
        # Update the prototype's status and feedback
        instance.status = validated_data.get('status', instance.status)
        instance.feedback = validated_data.get('feedback', instance.feedback)
        instance.save()
        return instance
