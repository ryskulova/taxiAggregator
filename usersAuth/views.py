import messages as messages
from django.contrib.auth import authenticate, login
from django.core.serializers import json
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.messages.views import SuccessMessageMixin
from rest_framework_jwt.views import ObtainJSONWebToken
from django.views.generic import FormView
from usersAuth.models import User
from .forms import RegisterForm, PhoneVerificationForm
from django.contrib import messages

from .serializers import JWTSerializer
# Create your views here.
class ObtainJWTView(ObtainJSONWebToken):
    serializer_class = JWTSerializer


class RegisterView(SuccessMessageMixin, FormView):
     form_class = RegisterForm
     success_message = "One-Time password sent to your registered mobile number.\
                        The verification code is valid for 10 minutes."


     def form_valid(self, form):
         user = form.save()
         username = self.request.POST['username']
         password = self.request.POST['password1']
         user = authenticate(username=username, password=password)
         try:
             response = send_verification_code(user)
         except Exception as e:
             from django.core.checks import messages
             messages.add_message(self.request, messages.ERROR,
                                  'verification code not sent. \n'
                                  'Please re-register.')
             return redirect('/register')
         data = json.loads(response.text)

         if data['success'] == False:
             messages.add_message(self.request, messages.ERROR,
                                  data['message'])

             return redirect ('/register')

         else:
             kwargs = {'user': user}
             self.request.method = 'GET'
             return PhoneVerificationView (self.request, **kwargs)

def PhoneVerificationView(request, **kwargs):

    if request.method == "POST":
        username = request.POST['username']
        user = User.objects.get(username=username)
        form = PhoneVerificationForm(request.POST)
        if form.is_valid():
            verification_code = request.POST['one_time_password']
            response = verify_sent_code(verification_code, user)
            print(response.text)
            data = json.loads(response.text)

            if data['success'] == True:
                login(request, user)
                if user.phone_number_verified is False:
                    user.phone_number_verified = True
                    user.save()
                return redirect('/dashboard')
            else:
                messages.add_message(request, messages.ERROR,
                                data['message'])
                return render(request, " ", {'user':user})
        else:
            context = {
                'user': user,
                'form': form,
            }
            return render(request, " ", context)

    elif request.method == "GET":
        try:
            user = kwargs['user']
            return render(request, " ", {'user': user})
        except:
            return HttpResponse("Not Allowed")


     

