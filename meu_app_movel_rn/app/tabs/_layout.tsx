// Conteúdo para: meu_app_movel_rn/app/(tabs)/_layout.tsx
import { Tabs, Redirect } from 'expo-router';
import React from 'react';
import { useAuth } from '../services/AuthContext'; // Ajuste o caminho

// Importe ícones se desejar usá-los nas abas
// import { Ionicons } from '@expo/vector-icons'; 
// Para usar Ionicons, instale: npx expo install @expo/vector-icons

export default function TabLayout() {
  const { userToken, isLoadingToken } = useAuth();

  // Enquanto verifica o token, não renderiza nada ou um loader
  if (isLoadingToken) {
    return null; // Ou <ActivityIndicator />; _layout.tsx raiz já tem um loader
  }

  // Se não há token E não está carregando, redireciona para login
  if (!userToken) {
    console.log("TabLayout: Sem token, redirecionando para login");
    return <Redirect href="/(auth)/login" />;
  }

  // Se tem token, renderiza as abas
  console.log("TabLayout: Usuário logado, renderizando abas.");
  return (
    <Tabs
      screenOptions={{
        // tabBarActiveTintColor: 'blue', // Exemplo
        headerShown: false, // Oculta cabeçalho padrão das abas
      }}>
      <Tabs.Screen
        name="index" // Corresponde a app/(tabs)/index.tsx
        options={{
          title: 'Dispositivos',
          // tabBarIcon: ({ color, focused }) => (
          //   <Ionicons name={focused ? 'home' : 'home-outline'} size={28} color={color} />
          // ),
        }}
      />
      {/* Exemplo de outra aba:
      <Tabs.Screen
        name="settings" // Corresponderia a app/(tabs)/settings.tsx
        options={{
          title: 'Configurações',
          // tabBarIcon: ({ color, focused }) => (
          //  <Ionicons name={focused ? 'settings' : 'settings-outline'} size={28} color={color} />
          // ),
        }}
      />
      */}
    </Tabs>
  );
}