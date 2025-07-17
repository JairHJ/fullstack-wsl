import { Component, Input, Output, EventEmitter, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CardModule } from 'primeng/card';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { MessageModule } from 'primeng/message';
import { AuthService } from '../../../core/auth/auth.service';
import { MfaInfo } from '../../../core/models/user.model';

@Component({
  selector: 'app-mfa-setup',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    CardModule,
    ButtonModule,
    InputTextModule,
    MessageModule
  ],
  template: `
    <div class="flex align-items-center justify-content-center min-h-screen">
      <p-card header="Configurar Autenticación de Dos Factores" styleClass="shadow-2" [style]="{ width: '500px' }">
        
        <div class="text-center mb-4">
          <h3>Escanea este código QR con Google Authenticator</h3>
          <p class="text-600 mb-3">
            1. Abre Google Authenticator en tu teléfono<br>
            2. Toca el botón "+" y selecciona "Escanear código QR"<br>
            3. Escanea el código QR de abajo
          </p>
          
          <div class="flex justify-content-center mb-3">
            <img [src]="'data:image/png;base64,' + mfaInfo.qr_code" 
                 alt="Código QR MFA" 
                 class="border-round shadow-2" 
                 style="width: 200px; height: 200px;" />
          </div>

          <p class="text-500 text-sm mb-3">
            Si no puedes escanear el código, puedes introducir manualmente esta clave:
          </p>
          <code class="bg-gray-100 p-2 border-round text-sm">{{ mfaInfo.secret }}</code>
        </div>

        <form [formGroup]="verificationForm" (ngSubmit)="onVerify()">
          <div class="field">
            <label for="otpCode">Código de verificación</label>
            <input 
              pInputText 
              id="otpCode" 
              formControlName="otpCode"
              class="w-full text-center"
              placeholder="Ingresa el código de 6 dígitos"
              maxlength="6" />
            
            <ng-container *ngIf="verificationForm.get('otpCode')?.invalid && verificationForm.get('otpCode')?.touched">
              <small class="p-error">Código de verificación es requerido</small>
            </ng-container>
          </div>

          <ng-container *ngIf="errorMessage()">
            <p-message 
              severity="error" 
              [text]="errorMessage()" 
              styleClass="w-full mb-3" />
          </ng-container>

          <div class="flex justify-content-between gap-2">
            <p-button 
              type="button"
              label="Saltar por ahora"
              severity="secondary"
              (onClick)="onSkip()"
              styleClass="flex-1" />
            
            <p-button 
              type="submit" 
              label="Verificar y Activar"
              [loading]="isLoading()"
              [disabled]="verificationForm.invalid || isLoading()"
              styleClass="flex-1" />
          </div>
        </form>
      </p-card>
    </div>
  `,
  styles: [`
    .field {
      margin-bottom: 1.5rem;
    }
    
    label {
      display: block;
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: var(--text-color);
    }
    
    .min-h-screen {
      min-height: 100vh;
      background: linear-gradient(135deg, var(--primary-50) 0%, var(--primary-100) 100%);
    }
  `]
})
export class MfaSetupComponent {
  @Input() mfaInfo!: MfaInfo;
  @Input() userId!: number;
  @Output() mfaCompleted = new EventEmitter<boolean>();
  @Output() mfaSkipped = new EventEmitter<void>();

  private fb = inject(FormBuilder);
  private authService = inject(AuthService);

  isLoading = signal(false);
  errorMessage = signal('');

  verificationForm: FormGroup = this.fb.group({
    otpCode: ['', [Validators.required, Validators.pattern(/^\d{6}$/)]]
  });

  onVerify() {
    if (this.verificationForm.valid) {
      this.isLoading.set(true);
      this.errorMessage.set('');

      const otpCode = this.verificationForm.value.otpCode;

      this.authService.enableMfa(this.userId, otpCode).subscribe({
        next: (result: {success: boolean, error?: string}) => {
          if (result.success) {
            this.mfaCompleted.emit(true);
          } else {
            this.errorMessage.set(result.error || 'Error al activar MFA');
          }
          this.isLoading.set(false);
        },
        error: () => {
          this.errorMessage.set('Error de conexión. Intenta nuevamente.');
          this.isLoading.set(false);
        }
      });
    }
  }

  onSkip() {
    this.mfaSkipped.emit();
  }
}
