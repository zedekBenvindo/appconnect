// Conteúdo para: meu_app_movel_rn/app/_layout.tsx
import React, { useEffect } from 'react';
import { SplashScreen, Stack, router } from 'expo-router';
import { AuthProvider, useAuth } from './services/AuthContext'; // Caminho para o AuthContext
import { ActivityIndicator, View, StyleSheet } from 'react-native';

SplashScreen.preventAutoHideAsync();

function RootNavigationDecider() {
  const { userToken, isLoadingToken } = useAuth();

  useEffect(() => {
    if (!isLoadingToken) {
      SplashScreen.hideAsync();
      if (userToken) {
        console.log("RootLayout: Usuário LOGADO, indo para (tabs)");
        router.replace('/(tabs)');
      } else {
        console.log("RootLayout: Usuário NÃO logado, indo para (auth)/login");
        router.replace('/(auth)/login');
      }
    }
  }, [userToken, isLoadingToken]);

  if (isLoadingToken) {
    return <View style={styles.loadingContainer}><ActivityIndicator size="large" color="#0000ff" /></View>;
  }

  // O Expo Router renderizará o grupo (auth) ou (tabs) baseado nos redirecionamentos acima
  // Este Stack é para configurar a apresentação desses grupos, se necessário.
  // Com headerShown: false, ele apenas permite que o conteúdo do grupo seja exibido.
  return (
      <Stack screenOptions={{ headerShown: false }}>
          <Stack.Screen name="(auth)" />
          <Stack.Screen name="(tabs)" />
      </Stack>
  );
}

export default function RootLayout() {
  return (
    <AuthProvider>
      <RootNavigationDecider />
    </AuthProvider>
  );
}

const styles = StyleSheet.create({
  loadingContainer: { flex: 1, justifyContent: 'center', alignItems: 'center' }
});