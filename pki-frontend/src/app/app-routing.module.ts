import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { EmailVerificationComponent } from './components/email-verification/email-verification.component';
import { AdminComponent } from './components/admin/admin.component';
import { ChangePasswordComponent } from './components/change-password/change-password.component';
import { AuthGuard } from './auth.guard';

const routes: Routes = [
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'verify-email', component: EmailVerificationComponent },
  { path: 'admin', component: AdminComponent, canActivate: [AuthGuard] },
  { path: 'change-password', component: ChangePasswordComponent, canActivate: [AuthGuard] },
  { path: '**', redirectTo: '/login' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
