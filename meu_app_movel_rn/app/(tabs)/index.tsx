// Conteúdo INICIAL para: meu_app_movel_rn/app/(tabs)/index.tsx
import { View, Text, Button, StyleSheet, Platform } from 'react-native';
import React from 'react';
import { useAuth } from '../services/AuthContext'; // Ajuste para subir um nível e depois entrar em services
import { Link } from 'expo-router'; // Se quiser link para outras partes

export default function MainAppScreenPlaceholder() {
  const { signOut, currentUser } = useAuth();

  return (
    <View style={styles.container}>
      <Text style={styles.title}>App Principal</Text>
      {currentUser && <Text style={styles.userInfo}>Logado como: {currentUser.username}</Text>}
      <Text style={styles.content}>Bem-vindo! A lista de dispositivos aparecerá aqui em breve.</Text>
      <Button title="Sair (Logout)" onPress={signOut} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20, paddingTop: Platform.OS === 'android' ? 40 : 60, backgroundColor: '#fff' },
  title: { fontSize: 22, fontWeight: 'bold', marginBottom: 20 },
  userInfo: { fontSize: 16, marginBottom: 10, color: 'gray' },
  content: { fontSize: 16, marginBottom: 20, textAlign: 'center' }
});