# services/barcode_service.py
from barcode import Code128
from barcode.writer import ImageWriter
import os

def generate_barcode(prototype_id):
    barcode = Code128(f'NM-{prototype_id}', writer=ImageWriter())
    filename = barcode.save(os.path.join('media', 'barcodes', f'NM-{prototype_id}'))
    return filename