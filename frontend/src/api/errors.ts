/**
 * Parses the backend's consistent error envelope:
 *   { detail: string, error_code: string | null, errors: {loc,msg,type}[] | null }
 * (see backend/app/main.py's exception handlers) into a single display
 * string, so every place that shows an API error does it the same way.
 */
import axios from 'axios';

interface ApiErrorBody {
  detail?: string;
  error_code?: string | null;
  errors?: { loc: string[]; msg: string; type: string }[] | null;
}

export function getApiErrorMessage(error: unknown, fallback = 'Something went wrong.'): string {
  if (!axios.isAxiosError(error)) {
    return fallback;
  }

  const body = error.response?.data as ApiErrorBody | undefined;

  if (body?.errors?.length) {
    return body.errors.map((e) => `${e.loc[e.loc.length - 1]}: ${e.msg}`).join(', ');
  }

  if (body?.detail) {
    return body.detail;
  }

  if (error.response?.status === 401) return 'Your session has expired. Please sign in again.';
  if (error.response?.status === 403) return 'You are not authorized to do that.';
  if (!error.response) return 'Could not reach the server. Check your connection.';

  return fallback;
}
