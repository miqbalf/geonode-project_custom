from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.decorators import permission_classes ,authentication_classes
from rest_framework.authentication import SessionAuthentication

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout

from .serializer import UserRegistrationSerializer

from geonode.base.auth import extract_headers, get_auth_token
from geonode.utils import json_response
from django.http import HttpResponse
import json

from allauth.account.utils import user_field, user_email, user_username

# Create your views here.
class HomeView(APIView):
    permission_classes = (IsAuthenticated, )
    #authentication_classes=( SessionAuthentication, )
    #permission_classes = [IsAuthenticated]
    def get(self, request):
        content = {'message': 'Welcome to the  \
                   Authentication page using React Js and Django!'}
        return Response(content)
'''

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
          
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

'''

## TRY WITH existing auth login django and implement registration process
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Create the user account using the serializer data
            serializer.save()
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response({"message": "Invalid request method."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(username=username, password=password)

    groups = [group.name for group in user.groups.all()]

    access_token = None

    if user:
        login(request, user)
        refresh = RefreshToken.for_user(user)
        access_token = get_auth_token(user)

        if user.is_superuser:
            groups.append("admin")

        
        return Response({
            "sub": str(user.id),
            "name": " ".join([user_field(user, "first_name"), user_field(user, "last_name")]),
            "given_name": user_field(user, "first_name"),
            "family_name": user_field(user, "last_name"),
            "email": user_email(user),
            "preferred_username": user_username(user),
            "groups": groups,
            "access_token": str(access_token),
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_200_OK)
    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


# example with using logout(request) from django auth
@api_view(['POST'])
def logout_user(request):
    logout(request)
    return Response({"message": "User logged out successfully."}, status=status.HTTP_200_OK)
