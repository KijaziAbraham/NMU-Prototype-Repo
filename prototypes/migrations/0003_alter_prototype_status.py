# Generated by Django 5.1.7 on 2025-04-01 21:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('prototypes', '0002_alter_prototype_supervisor'),
    ]

    operations = [
        migrations.AlterField(
            model_name='prototype',
            name='status',
            field=models.CharField(choices=[('submitted_not_reviewed', 'Submitted (Not Reviewed)'), ('submitted_reviewed', 'Submitted (Reviewed)')], default='submitted_not_reviewed', max_length=50),
        ),
    ]
