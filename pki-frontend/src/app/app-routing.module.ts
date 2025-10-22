import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { SplashScreenComponent } from './components/splash-screen/splash-screen.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { EmailVerificationComponent } from './components/email-verification/email-verification.component';
import { IssueCertificateComponent } from './components/issue-certificate/issue-certificate.component';
import { AdminComponent } from './components/admin/admin.component';
import { ChangePasswordComponent } from './components/change-password/change-password.component';
import { ForgotPasswordComponent } from './components/forgot-password/forgot-password.component';
import { ResetPasswordComponent } from './components/reset-password/reset-password.component';
import { AuthGuard } from './auth.guard';
import { TokensComponent } from './components/tokens/tokens.component';
import { TemplateComponent } from './components/template/template.component';
import { CsrUploadComponent } from './components/csr-upload/csr-upload.component';
import { CsrListComponent } from './components/csr-list/csr-list.component';
import { PasswordManagerComponent } from './components/password-manage/password-manage.component';
import { CertificateListComponent } from './components/certificate-list/certificate-list.component';

const routes: Routes = [
  { path: '', redirectTo: '/splash', pathMatch: 'full' },
  { path: 'splash', component: SplashScreenComponent },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'tokens', component: TokensComponent },
  { path: 'verify-email', component: EmailVerificationComponent },
  { path: 'issue-certificate', component: IssueCertificateComponent },
  { path: 'csr/upload', component: CsrUploadComponent },
    { path: 'password-manager', component: PasswordManagerComponent, canActivate: [AuthGuard] },
  { path: 'csr/list-pending', component: CsrListComponent, canActivate: [AuthGuard] },
  { path: 'admin', component: AdminComponent, canActivate: [AuthGuard] },
  { path: 'change-password', component: ChangePasswordComponent, canActivate: [AuthGuard] },
  { path: 'forgot-password', component: ForgotPasswordComponent },
  { path: 'reset-password', component: ResetPasswordComponent },
  { path: 'certificates', component: CertificateListComponent },
  { path: 'template', component: TemplateComponent },
  { path: '**', redirectTo: '/splash' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
