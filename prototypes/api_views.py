from django.contrib.auth import get_user_model, authenticate
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

def get_tokens_for_user(user):
    """Generate JWT access and refresh tokens for a user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['POST'])
@permission_classes([AllowAny])  
def register_user(request):
    """Register a new user and return JWT tokens"""
    email = request.data.get("email")
    password = request.data.get("password")
    
    if not email or not password:
        return Response({"error": "Email and password required"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({"error": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=email, email=email, password=password)
    tokens = get_tokens_for_user(user)
    
    return Response({"message": "User created successfully", "tokens": tokens}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny]) 
def login_user(request):
    """Authenticate user and return JWT tokens"""
    email = request.data.get("email")
    password = request.data.get("password")

    user = authenticate(username=email, password=password)
    
    if user is None:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    
    tokens = get_tokens_for_user(user)
    return Response({"message": "Login successful", "tokens": tokens}, status=status.HTTP_200_OK)


