// Conteúdo para: meu_app_movel_rn/app/(tabs)/_layout.tsx
import { Tabs, Redirect } from 'expo-router';
import React from 'react';
import { useAuth } from '../../contexts/AuthContext'; // <<< CAMINHO ATUALIZADO
// import { Ionicons } from '@expo/vector-icons'; // Para ícones nas abas

export default function TabLayout() {
  const { userToken, isLoadingToken } = useAuth();

  if (isLoadingToken) return null; // Loader já está no layout raiz
  if (!userToken) return <Redirect href="/(auth)/login" />; // Proteção extra

  return (
    <Tabs screenOptions={{ headerShown: false, /* tabBarActiveTintColor: 'blue' */ }}>
      <Tabs.Screen name="index" options={{ title: 'Dispositivos', /* tabBarIcon: ... */ }} />
      {/* <Tabs.Screen name="settings" options={{ title: 'Ajustes', tabBarIcon: ... }} /> */}
    </Tabs>
  );
}