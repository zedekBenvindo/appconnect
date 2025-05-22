// Conteúdo INICIAL SIMPLES para App.js/App.tsx ou app/index.tsx
import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, FlatList, ActivityIndicator, Platform } from 'react-native';

// !!! AJUSTE SEU IP LOCAL DO COMPUTADOR AQUI !!!
const BACKEND_URL = 'http://192.168.1.15:5000';

interface Device {
  id: number;
  name: string;
  status: string;
}

export default function App() { // Ou o nome do seu componente principal
  const [isLoading, setIsLoading] = useState(true);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDummyDevices = async () => {
      setIsLoading(true);
      setError(null);
      console.log(`Frontend: Buscando de: ${BACKEND_URL}/api/devices`);
      try {
        const response = await fetch(`${BACKEND_URL}/api/devices`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: Device[] = await response.json();
        console.log("Frontend: Recebidos (dummy):", data);
        setDevices(data);
      } catch (e: any) {
        console.error("Frontend: Erro buscar (dummy):", e);
        setError(`Falha ao carregar: ${e.message || 'Erro desconhecido'}`);
        setDevices([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchDummyDevices();
  }, []);

  if (isLoading) {
    return <View style={styles.center}><ActivityIndicator size="large" /></View>;
  }
  if (error) {
    return <View style={styles.center}><Text style={styles.errorText}>{error}</Text></View>;
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Lista de Dispositivos (Dummy)</Text>
      <FlatList
        data={devices}
        keyExtractor={item => item.id.toString()}
        renderItem={({ item }) => (
          <View style={styles.item}>
            <Text>{item.name} - Status: {item.status}</Text>
          </View>
        )}
        ListEmptyComponent={<Text>Nenhum dispositivo encontrado.</Text>}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingTop: Platform.OS === 'android' ? 60 : 80, // Aumentado o paddingTop
    paddingHorizontal: 20,
    backgroundColor: '#fff',
  },
  center: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  item: {
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  errorText: {
    color: 'red',
  }
});