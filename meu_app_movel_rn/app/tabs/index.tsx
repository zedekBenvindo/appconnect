// Conteúdo INICIAL para: meu_app_movel_rn/app/(tabs)/index.tsx
import { View, Text, Button, StyleSheet } from 'react-native';
import React from 'react';
import { useAuth } from '../services/AuthContext'; // Ajuste o caminho

export default function MainAppScreenPlaceholder() {
  const { signOut, currentUser } = useAuth();

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Tela Principal (Dispositivos)</Text>
      {currentUser && <Text style={styles.userInfo}>Logado como: {currentUser.username}</Text>}
      <Text style={styles.content}>A lista de dispositivos aparecerá aqui!</Text>
      <Button title="Sair (Logout)" onPress={signOut} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20, backgroundColor: '#fff' },
  title: { fontSize: 22, fontWeight: 'bold', marginBottom: 20 },
  userInfo: { fontSize: 16, marginBottom: 10 },
  content: { fontSize: 16, marginBottom: 20, textAlign: 'center' }
});