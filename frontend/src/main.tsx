import React from 'react';
import ReactDOM from 'react-dom/client';
import { KeycloakProvider } from '@/auth/KeycloakProvider';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AuthProvider } from '@/hooks/useAuth';
import { ThemeProvider } from '@/theme/ThemeProvider';
import App from './App';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});


ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThemeProvider>
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <QueryClientProvider client={queryClient}>
        <KeycloakProvider>
          <AuthProvider>
            <App />
          </AuthProvider>
        </KeycloakProvider>
      </QueryClientProvider>
    </BrowserRouter>
    </ThemeProvider>
  </React.StrictMode>
);
