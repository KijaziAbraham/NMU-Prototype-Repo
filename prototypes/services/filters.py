import django_filters
from .models import Prototype

class PrototypeFilter(django_filters.FilterSet):
    academic_year = django_filters.CharFilter(
        field_name='academic_year',
        lookup_expr='exact'
    )
    status = django_filters.MultipleChoiceFilter(
        choices=Prototype.STATUS_CHOICES
    )
    has_physical = django_filters.BooleanFilter()
    department = django_filters.CharFilter(
        field_name='department__code'
    )
    student = django_filters.CharFilter(
        field_name='student__email'
    )

    class Meta:
        model = Prototype
        fields = [
            'academic_year', 'status',
            'has_physical', 'department',
            'student'
        ]