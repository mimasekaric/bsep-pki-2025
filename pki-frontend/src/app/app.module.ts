import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { EmailVerificationComponent } from './components/email-verification/email-verification.component';
import { IssueCertificateComponent } from './components/issue-certificate/issue-certificate.component';
import { HttpClientModule } from '@angular/common/http';
import { AuthGuard } from './auth.guard';
import { TokensComponent } from './components/tokens/tokens.component';
import { AuthInterceptor } from '../app/inceptors/auth.inceptor';
import { AuthService } from './services/auth.service';
import {HTTP_INTERCEPTORS } from '@angular/common/http';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    EmailVerificationComponent,
    IssueCertificateComponent,
    TokensComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule,
    FormsModule
  ],
   providers: [
    AuthService, // Pruži AuthService ako ga koristiš za logout
    {
      provide: HTTP_INTERCEPTORS, // Angular token za interceptore
      useClass: AuthInterceptor,  // Tvoja klasa interceptora
      multi: true                 // Omogućava dodavanje više interceptora
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
