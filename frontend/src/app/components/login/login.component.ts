import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  standalone: true
})
export class LoginComponent implements OnInit {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // Check if user is already authenticated
    this.authService.checkAuthStatus().subscribe({
      next: () => {
        if (this.authService.isAuthenticated()) {
          this.router.navigate(['/dashboard']);
        }
      },
      error: () => {
        // User not authenticated, stay on login page
      }
    });
  }

  loginWithGoogle(): void {
    this.authService.login();
  }
}