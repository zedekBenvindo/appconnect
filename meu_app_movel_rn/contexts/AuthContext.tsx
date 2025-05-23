// Conteúdo para: meu_app_movel_rn/contexts/AuthContext.tsx
import React, { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import * as SecureStore from 'expo-secure-store';
import { Alert } from 'react-native';

// !!! AJUSTE SEU IP LOCAL DO COMPUTADOR AQUI !!!
export const BACKEND_URL: string = 'http://192.168.1.15:5000'; // EXPORTADO AGORA
const TOKEN_KEY = 'user-auth-token-v1.3'; // Nova chave para resetar se necessário

interface User { id: string; username: string; }
interface AuthContextType {
  userToken: string | null;
  currentUser: User | null;
  isLoadingToken: boolean;
  signIn: (usernameInput: string, passwordInput: string) => Promise<boolean>;
  signOut: () => Promise<void>;
  signUp: (usernameInput: string, passwordInput: string) => Promise<{ success: boolean; message: string }>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{children: ReactNode}> = ({ children }) => {
  const [isLoadingToken, setIsLoadingToken] = useState(true);
  const [userToken, setUserToken] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  useEffect(() => {
    const bootstrapAsync = async () => {
      let tokenFromStore: string | null = null;
      try {
        tokenFromStore = await SecureStore.getItemAsync(TOKEN_KEY);
        if (tokenFromStore) {
          setUserToken(tokenFromStore);
          // TODO: Decodificar token para pegar dados reais do usuário ou chamar API /me
          // Por enquanto, simulamos:
          // Ex: const decoded = jwt_decode(tokenFromStore); setCurrentUser({ id: decoded.user_id, username: decoded.username });
          setCurrentUser({ id: 'user_from_store_id', username: 'Usuário Persistido' });
          console.log("AuthProvider: Token carregado do SecureStore.");
        }
      } catch (e) { console.error("AuthProvider: Erro ao restaurar token", e); }
      setIsLoadingToken(false);
    };
    bootstrapAsync();
  }, []);

  const signIn = async (usernameInput: string, passwordInput: string): Promise<boolean> => {
    setIsLoadingToken(true);
    try {
      const response = await fetch(`${BACKEND_URL}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: usernameInput, password: passwordInput }), });
      const data = await response.json();
      if (response.ok && data.access_token) {
        await SecureStore.setItemAsync(TOKEN_KEY, data.access_token);
        setUserToken(data.access_token);
        // Supondo que o backend retorne user_id no payload do token ou na resposta do login
        // Se não, você precisaria decodificar o token ou buscar user info numa rota /me
        // O username já temos, o id pode ser o do payload do token
        setCurrentUser({ id: data.user_id_from_token || "logged_in_user_id", username: usernameInput });
        console.log("AuthProvider: Login bem-sucedido.");
        setIsLoadingToken(false); return true;
      } else { Alert.alert("Erro Login", data.message || "Falha no login."); setIsLoadingToken(false); return false; }
    } catch (e:any) { Alert.alert("Erro Login", e.message || "Falha de conexão."); setIsLoadingToken(false); return false; }
  };
  const signOut = async () => {
    setIsLoadingToken(true); await SecureStore.deleteItemAsync(TOKEN_KEY);
    setUserToken(null); setCurrentUser(null); setIsLoadingToken(false);
    console.log("AuthProvider: Usuário deslogado.");
  };
  const signUp = async (usernameInput: string, passwordInput: string): Promise<{ success: boolean; message: string }> => {
      setIsLoadingToken(true);
      try {
          const response = await fetch(`${BACKEND_URL}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: usernameInput, password: passwordInput }), });
          const data = await response.json(); setIsLoadingToken(false);
          if (response.ok || response.status === 201) return { success: true, message: data.message || "Registrado!" };
          else return { success: false, message: data.message || "Falha registro." };
      } catch (e:any) { setIsLoadingToken(false); return { success: false, message: e.message || "Falha conexão registro." }; }
  };
  return <AuthContext.Provider value={{ userToken, currentUser, isLoadingToken, signIn, signOut, signUp }}>{children}</AuthContext.Provider>;
};
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) throw new Error('useAuth deve ser usado dentro de um AuthProvider');
  return context;
};