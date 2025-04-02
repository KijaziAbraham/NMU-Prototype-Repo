import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.validators import FileExtensionValidator
from django.forms import ValidationError
from django.utils.translation import gettext_lazy as _
from django.db import models
import os
import hashlib


class Department(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.code} - {self.name}"

#custom user for the system log in with email and password
# and also to be used for the prototype submission
class CustomUser(AbstractUser):
    ROLES = (
        ('admin', 'Administrator'),
        ('staff', 'Faculty/Staff'),
        ('student', 'Student'),
    )
    
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLES)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    institution_id = models.CharField(max_length=50, blank=True)

    USERNAME_FIELD = 'email'   # Use email as the username field an d is unique
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ['-date_joined']

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

#model for submission of project (prototypes) by students
# and also for the review process by the faculty/staff
class Prototype(models.Model):
    STATUS_CHOICES = [
        ('submitted_not_reviewed', 'Submitted (Not Reviewed)'),
        ('submitted_reviewed', 'Submitted (Reviewed)'),  
    ]
#further changes should be done here to make status be allways true since all project submitted here are approved
    student = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='prototypes',
        limit_choices_to={'role': 'student'}
    )
    title = models.CharField(max_length=255)
    abstract = models.TextField()
    department = models.ForeignKey(Department, on_delete=models.PROTECT)
    academic_year = models.CharField(max_length=9)  #Format: 2023/2024
    supervisor = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="supervised_prototypes",
        limit_choices_to={'role': 'staff'}
    )
    submission_date = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='submitted_not_reviewed') #further changes should be done here to make status be allways true since all project submitted here are approved

    has_physical_prototype = models.BooleanField(default=False)
    barcode = models.CharField(max_length=50, unique=True, blank=True, null=True)
    storage_location = models.CharField(max_length=100, blank=True)
    feedback = models.TextField(blank=True)
    reviewer = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_prototypes',
        limit_choices_to={'role__in': ['staff', 'admin']}
    )

    class Meta:
        ordering = ['-submission_date']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['barcode']),
            models.Index(fields=['academic_year']),
        ]

    def __str__(self):
        return f"{self.title} ({self.student.email})"

    def save(self, *args, **kwargs):
        if self.has_physical_prototype and not self.barcode:
            self.barcode = f"NM-{self.department.code}-{uuid.uuid4().hex[:8].upper()}"
        super().save(*args, **kwargs)




class PrototypeAttachment(models.Model):
    FILE_TYPE_CHOICES = [
        ('report', 'Final Report'),
        ('source', 'Source Code'),
        ('presentation', 'Presentation'),
        ('dataset', 'Dataset'),
        ('documentation', 'Documentation'),
        ('other', 'Other')
    ]

    EXTENSION_MAP = {
        'report': ['pdf', 'doc', 'docx', 'odt'],
        'source': ['zip', 'rar', 'tar', 'gz', '7z', 'py', 'java', 'cpp'],
        'presentation': ['ppt', 'pptx', 'odp', 'key'],
        'dataset': ['csv', 'xls', 'xlsx', 'json', 'sql', 'db'],
        'documentation': ['md', 'txt', 'html'],
        'other': ['jpg', 'png', 'mp4', 'mov', 'stl', 'obj']
    }

    prototype = models.ForeignKey(
        'Prototype',
        related_name='attachments',
        on_delete=models.CASCADE
    )
    file_type = models.CharField(
        max_length=15,
        choices=FILE_TYPE_CHOICES
    )
    file = models.FileField(
        upload_to='prototype_attachments/%Y/%m/%d/',
        validators=[FileExtensionValidator(
            allowed_extensions=sum(EXTENSION_MAP.values(), []) #aaray passing multiple files at once
        )]
    )
    description = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    size = models.PositiveIntegerField(editable=False)
    checksum = models.CharField(max_length=64, blank=True, editable=False)

    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'Prototype Attachment'
        verbose_name_plural = 'Prototype Attachments'

    def save(self, *args, **kwargs):
        if not self.pk:
            self.size = self.file.size
            self.checksum = self.calculate_checksum()
            self.validate_file_type()
        super().save(*args, **kwargs)

    def calculate_checksum(self):
        sha256 = hashlib.sha256()
        for chunk in self.file.chunks():
            sha256.update(chunk)
        return sha256.hexdigest()

    def validate_file_type(self):
        ext = os.path.splitext(self.file.name)[1][1:].lower()
        if ext not in self.EXTENSION_MAP[self.file_type]:
            raise ValidationError(
                f"Invalid extension for {self.get_file_type_display()}. "
                f"Allowed: {', '.join(self.EXTENSION_MAP[self.file_type])}"
            )

    @property
    def filename(self):
        return os.path.basename(self.file.name)

    def __str__(self):
        return f"{self.get_file_type_display()} - {self.filename}"
    
class AuditLog(models.Model):
    ACTIONS = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('login', 'Login'),
        ('download', 'Download'),
        ('review', 'Review')
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=10, choices=ACTIONS)
    model = models.CharField(max_length=50)
    object_id = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['model', 'object_id']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.user} {self.action} {self.model}:{self.object_id}"
    
