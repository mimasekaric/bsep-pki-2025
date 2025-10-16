import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { EmailVerificationComponent } from './components/email-verification/email-verification.component';
import { HttpClientModule } from '@angular/common/http';
import { AuthGuard } from './auth.guard';
import { AdminComponent } from './components/admin/admin.component';
import { ChangePasswordComponent } from './components/change-password/change-password.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    EmailVerificationComponent,
    AdminComponent,
    ChangePasswordComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
