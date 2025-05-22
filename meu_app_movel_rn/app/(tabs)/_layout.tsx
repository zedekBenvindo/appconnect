// Conteúdo para: meu_app_movel_rn/app/(tabs)/_layout.tsx
import { Tabs, Redirect } from 'expo-router';
import React from 'react';
import { useAuth } from '../services/AuthContext'; // Ajuste para subir um nível e depois entrar em services

// Se quiser usar ícones:
// import { Ionicons } from '@expo/vector-icons';
// Para usar Ionicons, instale: npx expo install @expo/vector-icons

export default function TabLayout() {
  const { userToken, isLoadingToken } = useAuth();

  if (isLoadingToken) {
    return null; // Ou um loader, mas o _layout.tsx raiz já deve ter um
  }

  if (!userToken) {
    // Não deveria chegar aqui se o _layout.tsx raiz estiver funcionando,
    // mas é uma proteção extra.
    console.log("TabLayout: Usuário não logado, redirecionando para login (proteção extra)");
    return <Redirect href="/(auth)/login" />;
  }

  return (
    <Tabs screenOptions={{ headerShown: false, /* tabBarActiveTintColor: 'blue' */ }}>
      <Tabs.Screen
        name="index" // Corresponde a app/(tabs)/index.tsx
        options={{
          title: 'Dispositivos',
          // tabBarIcon: ({ color, focused }) => (
          //   <Ionicons name={focused ? 'list-circle' : 'list-circle-outline'} size={28} color={color} />
          // ),
        }}
      />
      {/* Adicione outras abas aqui, como Configurações
      <Tabs.Screen
        name="settings" // Corresponderia a app/(tabs)/settings.tsx
        options={{
          title: 'Config',
          // tabBarIcon: ({ color, focused }) => (
          //   <Ionicons name={focused ? 'settings' : 'settings-outline'} size={28} color={color} />
          // ),
        }}
      />
      */}
    </Tabs>
  );
}