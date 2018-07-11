from django import forms
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.messages.views import SuccessMessageMixin
from django.core.checks import messages
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate, login
from django.views import View
from django.views.generic import FormView

from usersAuth.views import PhoneVerificationView
from .models import User


class RegisterForm(forms.ModelForm):
    phone_number = forms.IntegerField(required=True)
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(widget=forms.PasswordInput())
    country_code = forms.Integer()

    MIN_LENCTH = 4

    class Meta:
        model = User
        fields = ['username', 'country_code', 'phone_number', 'password1', 'password2', 'full_name']


    def clean_username(self):
        username = self.data.get('username')
        return username

    def clean_password1(self):
        password = self.data.get('password1')
        validate_password(password)
        if password != self.data.get('password2'):
            raise forms.ValidationError(_("Password do not match"))
        return password

    def clean_phone_number(self):
        phone_number = self.data.get('phone_number')
        if User.objects.filter(phone_number=phone_number).exists():
            raise forms.ValidationError(
                _("Another user with this phone number already" ))
        return phone_number


    def save(self, *args, **kwargs):
        user = super(RegisterForm, self).save(*args, **kwargs)
        user.set_password(self.cleaned_data['password1'])
        user.save()
        return user


  class PhoneVerificationForm(forms.Form):
        one_time_password = forms.IntegerField()

        class Meta:
            fields = ['one_time_password']


  class LoginForm(forms.Form):
      username = forms.CharField()
      password = forms.CharField()

      class Meta:
          fields = ['username', 'password']

      def clean(self):
          username = self.cleaned_data.get('username')
          password = self.cleaned_data.get('password')
          user = authenticate(username=username, password=password)
          if not user:
              raise forms.ValidationError("Sorry, that login was invalid. Please try again.")
          return self.cleaned_data

      def login(self, request):
          username = self.cleaned_data.get('username')
          password = self.cleaned_data.get('password')
          user = authenticate(username=username, password=password)
          return user


class  LoginView(FormView):
      form_class = LoginForm
      success_url = '/dashboard'


      def dispatch(self, request, *args, **kwargs):
          if self.request.user.is_authenticated:
              messages.add_message(self.request, messages.INFO,
                                    "User already logged in ")
              return redirect('/dashboard')
          else:
              return super().dispatch(request, *args, **kwargs)


      def form_valid(self, form):
          user = form.login(self.request)
          if user.two_factor_auth is False:
              login(self.request, user)
              return redirect('/dashboard')

          else:
             try:
                 response = send_verification_code(user)
                 pass
             except Exception  as e:
                 messages.add_message(self.request, messages.ERROR,
                                      data['message'])
                 return redirect('/login')

          if data['success'] == True:
              self.request.method = "GET"
              print (self.request.method)
              kwargs = {'user': user}
              return PhoneVerificationView (self.request, **kwargs)
          else:
              messages.add_message (self.request, messages.ERROR,
                                    data['message'])
              return redirect ('/login')




@method_decorator (login_required (login_url="/login/"), name='dispatch')
class DashboardView (SuccessMessageMixin, View):
              def get(self, request):
                  context = {
                      'user': self.request.user,
                  }
                  if not request.user.phone_number_verified:
                      messages.add_message (self.request, messages.INFO,
                                            "User Not verified.")
                  return render (self.request, self.template_name, context)

              def post(self, request):
                  if 'two_factor_auth' in request.POST:
                      if request.user.two_factor_auth:
                          request.user.two_factor_auth = False
                      else:
                          request.user.two_factor_auth = True
                      request.user.save ()

                  return render (self.request, " ", {})



