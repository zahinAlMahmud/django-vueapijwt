from django.shortcuts import render
# Create your views here.
from rest_framework .views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
from django.contrib.auth.models import User
from  rest_framework.permissions import AllowAny,IsAuthenticated
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken


class LoginView(APIView):
    permission_classes =[AllowAny]

    def post(self,request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')          
            try:
                user = User.objects.get(username=username)
                if check_password(password,user.password):
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh':str(refresh),
                        'access':str(refresh.access_token),
                    })
                return Response({'error':'Invalid credentials'},status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({'error':"Not Found"},status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
               