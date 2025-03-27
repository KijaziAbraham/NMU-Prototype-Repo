from django.template.loader import render_to_string
from weasyprint import HTML
import tempfile
import os
from django.conf import settings

def generate_prototype_report(prototype):
    """Generate PDF report for a prototype"""
    context = {
        'prototype': prototype,
        'attachments': prototype.attachments.all()
    }
    
    html_string = render_to_string('reports/prototype_report.html', context)
    html = HTML(string=html_string, base_url=settings.BASE_DIR)
    
    temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_reports')
    os.makedirs(temp_dir, exist_ok=True)
    
    output_file = os.path.join(temp_dir, f'report_{prototype.barcode}.pdf')
    html.write_pdf(output_file)
    
    return output_file