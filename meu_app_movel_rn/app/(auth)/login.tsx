// Conteúdo para: meu_app_movel_rn/app/(auth)/login.tsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, ActivityIndicator, Alert, TouchableOpacity } from 'react-native';
import { useAuth } from '../../contexts/AuthContext'; // <<< CAMINHO ATUALIZADO
import { Link } from 'expo-router';

export default function LoginScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { signIn, isLoadingToken } = useAuth();

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) { Alert.alert("Login", "Usuário e senha obrigatórios."); return; }
    await signIn(username, password);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Entrar</Text>
      <TextInput style={styles.input} placeholder="Nome de Usuário" value={username} onChangeText={setUsername} autoCapitalize="none" keyboardType="email-address" />
      <TextInput style={styles.input} placeholder="Senha" value={password} onChangeText={setPassword} secureTextEntry />
      {isLoadingToken ? (<ActivityIndicator size="large" color="#007AFF" />) : (<Button title="Entrar" onPress={handleLogin} />)}
      <Link href="/(auth)/register" asChild style={styles.linkContainer}>
        <TouchableOpacity><Text style={styles.linkText}>Não tem uma conta? Registre-se</Text></TouchableOpacity>
      </Link>
    </View>
  );
}
const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', padding: 30, backgroundColor: '#fff' },
  title: { fontSize: 28, fontWeight: 'bold', textAlign: 'center', marginBottom: 40, color: '#333' },
  input: { height: 50, borderColor: '#ccc', borderWidth: 1, marginBottom: 20, paddingHorizontal: 15, borderRadius: 8, backgroundColor: '#f9f9f9', fontSize: 16 },
  linkContainer: { marginTop: 25, alignItems: 'center' },
  linkText: { color: '#007AFF', fontSize: 16 }
});