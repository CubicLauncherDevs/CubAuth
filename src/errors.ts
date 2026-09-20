export interface ErrorDetails {
  service: 'supabase';
  operation: string;
  upstreamStatus?: number;
  upstreamCode?: string;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: ErrorDetails) {
    super(message);
    this.name = code;
  }
}

export const invalidToken = () => new ApiError(403, 'ForbiddenOperationException', 'Invalid token.');
export const invalidCredentials = () => new ApiError(403, 'ForbiddenOperationException', 'Invalid credentials. Invalid username or password.');
export const badRequest = (message: string) => new ApiError(400, 'IllegalArgumentException', message);
