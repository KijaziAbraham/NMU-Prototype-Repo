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
        limit_choices_to={'role__in': ['staff', 'admin']}
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




#model for the attachment of files to the project (prototypes) by students
class PrototypeAttachment(models.Model):
    prototype = models.OneToOneField(Prototype, on_delete=models.CASCADE, related_name="attachment")
    report = models.FileField(upload_to='prototypes/reports/', validators=[FileExtensionValidator(['pdf'])])
    source_code = models.FileField(upload_to='prototypes/source_code/', validators=[FileExtensionValidator(['zip'])])

    def __str__(self):
        return f"Attachments for {self.prototype.title}"

