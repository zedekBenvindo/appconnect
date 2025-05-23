// Conteúdo para: meu_app_movel_rn/app/(auth)/_layout.tsx
import { Stack } from 'expo-router';
import React from 'react';

export default function AuthFlowLayout() {
  return (
    <Stack>
      <Stack.Screen name="login" options={{ headerShown: false }} />
      <Stack.Screen name="register" options={{ title: "Criar Nova Conta", headerBackTitle: "Login" }} />
    </Stack>
  );
}