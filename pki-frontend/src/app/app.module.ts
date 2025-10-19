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
import { CsrUploadComponent } from './components/csr-upload/csr-upload.component';
import { CsrListComponent } from './components/csr-list/csr-list.component';
import { NavbarComponent } from './layout/navbar/navbar.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ApproveDialogComponent } from './components/approve-dialog.component.ts/approve-dialog.component.ts.component';
import { AdminComponent } from './components/admin/admin.component';
import { ChangePasswordComponent } from './components/change-password/change-password.component';



@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    ApproveDialogComponent,
    EmailVerificationComponent,
    IssueCertificateComponent,
    TokensComponent,
    CsrUploadComponent,
    CsrListComponent,
    NavbarComponent,
    ApproveDialogComponent,
    EmailVerificationComponent,
    AdminComponent,
    ChangePasswordComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatSelectModule,
    MatInputModule,
    MatProgressSpinnerModule,
    BrowserAnimationsModule
    
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
