// app/core/auth/auth.interceptor.ts
import { HttpRequest, HttpHandlerFn, HttpEvent } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

export const authInterceptor: any = (req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> => {
  // El interceptor maneja directamente el token
  const token = localStorage.getItem('token');

  let authReq = req;

  // Agregar token a las peticiones si existe
  if (token) {
    authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(authReq).pipe(
    tap(event => {
      // Interceptar respuestas para extraer y guardar tokens
      if (event.type === 4) { // HttpEventType.Response
        const response = event as any;
        if (response.body?.proxied_response?.access_token) {
          localStorage.setItem('token', response.body.proxied_response.access_token);
        }
      }
    })
  );
};
