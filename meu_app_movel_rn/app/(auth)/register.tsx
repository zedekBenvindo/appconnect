// Conteúdo para: meu_app_movel_rn/app/(auth)/register.tsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, ActivityIndicator, Alert, TouchableOpacity } from 'react-native';
import { useAuth } from '../../contexts/AuthContext'; // <<< CAMINHO ATUALIZADO
import { router } from 'expo-router';

export default function RegisterScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const { signUp, isLoadingToken } = useAuth();

  const handleRegister = async () => {
    if (!username.trim() || !password.trim()) { Alert.alert("Registro", "Usuário e senha obrigatórios."); return; }
    if (password !== confirmPassword) { Alert.alert("Registro", "As senhas não coincidem."); return; }
    const result = await signUp(username, password);
    if (result.success) { Alert.alert("Sucesso!", result.message || "Usuário registrado! Por favor, faça o login."); router.replace('/(auth)/login'); }
    else { Alert.alert("Erro no Registro", result.message || "Não foi possível registrar."); }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Criar Conta</Text>
      <TextInput style={styles.input} placeholder="Nome de Usuário" value={username} onChangeText={setUsername} autoCapitalize="none" />
      <TextInput style={styles.input} placeholder="Senha" value={password} onChangeText={setPassword} secureTextEntry />
      <TextInput style={styles.input} placeholder="Confirmar Senha" value={confirmPassword} onChangeText={setConfirmPassword} secureTextEntry />
      {isLoadingToken ? (<ActivityIndicator size="large" color="#007AFF" />) : (<Button title="Registrar" onPress={handleRegister} />)}
      <TouchableOpacity onPress={() => router.back()} style={styles.linkContainer}><Text style={styles.linkText}>Já tem uma conta? Voltar para Login</Text></TouchableOpacity>
    </View>
  );
}
const styles = StyleSheet.create({ /* Mesmos estilos do login.tsx */
  container: { flex: 1, justifyContent: 'center', padding: 30, backgroundColor: '#fff' },
  title: { fontSize: 28, fontWeight: 'bold', textAlign: 'center', marginBottom: 40, color: '#333' },
  input: { height: 50, borderColor: '#ccc', borderWidth: 1, marginBottom: 20, paddingHorizontal: 15, borderRadius: 8, backgroundColor: '#f9f9f9', fontSize: 16 },
  linkContainer: { marginTop: 25, alignItems: 'center' },
  linkText: { color: '#007AFF', fontSize: 16 }
});