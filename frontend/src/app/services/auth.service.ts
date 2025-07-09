import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';

export interface User {
  name: string;
  email: string;
  authenticated: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_BASE = '/api/auth';
  private userSubject = new BehaviorSubject<User | null>(null);
  public user$ = this.userSubject.asObservable();

  constructor(private http: HttpClient) {
    this.checkAuthStatus();
  }

  login(): void {
    window.location.href = `${this.API_BASE}/google-login`;
  }

  logout(): void {
    window.location.href = '/logout';
  }

  checkAuthStatus(): Observable<any> {
    return this.http.get(`${this.API_BASE}/logged-in`, { responseType: 'text' })
      .pipe(
        tap((response: string) => {
          if (response.startsWith('Hi ')) {
            const name = response.replace('Hi ', '').replace(', you are logged in', '');
            this.userSubject.next({
              name: name,
              email: '', // Backend doesn't return email in this response
              authenticated: true
            });
          }
        }),
        catchError((error) => {
          this.userSubject.next(null);
          throw error;
        })
      );
  }

  isAuthenticated(): boolean {
    return this.userSubject.value?.authenticated || false;
  }

  getUser(): User | null {
    return this.userSubject.value;
  }
}