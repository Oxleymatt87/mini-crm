/**
 * Oxley XR — WebView wrapper with bottom tab navigation.
 */

import React from 'react';
import {
  Linking,
  Pressable,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { NavigationContainer } from '@react-navigation/native';
import {
  createBottomTabNavigator,
  BottomTabNavigationOptions,
} from '@react-navigation/bottom-tabs';
import { WebView } from 'react-native-webview';

const URLS = {
  Map: 'https://inventory-setup-b3f20.web.app/map-xr.html',
  Customers: 'https://inventory-setup-b3f20.web.app/customers.html',
  Ledger: 'https://inventory-setup-b3f20.web.app/ledger.html',
  Inventory: 'https://inventory-setup-b3f20.web.app/intake.html',
  Dashboard: 'https://inventory-setup-b3f20.web.app/index.html',
} as const;

type TabName = keyof typeof URLS;

const TAB_ICONS: Record<TabName, string> = {
  Map: '🗺',
  Customers: '👥',
  Ledger: '📒',
  Inventory: '📦',
  Dashboard: '📊',
};

function WebViewScreen({ url }: { url: string }) {
  return (
    <View style={styles.flex}>
      <WebView
        source={{ uri: url }}
        style={styles.flex}
        javaScriptEnabled
        domStorageEnabled
        allowsInlineMediaPlayback
        mediaPlaybackRequiresUserAction={false}
        originWhitelist={['*']}
        startInLoadingState
      />
    </View>
  );
}

// Map tab gets an overlay button that opens map-xr.html in the system
// browser, where Chromium has WebXR enabled and "Enter AR" actually
// launches an immersive session. The WebView itself is fine for browsing.
function MapScreen() {
  const openExternal = React.useCallback(() => {
    Linking.openURL(URLS.Map).catch(() => {
      /* silently ignore — system browser unavailable */
    });
  }, []);

  return (
    <View style={styles.flex}>
      <WebView
        source={{ uri: URLS.Map }}
        style={styles.flex}
        javaScriptEnabled
        domStorageEnabled
        allowsInlineMediaPlayback
        mediaPlaybackRequiresUserAction={false}
        originWhitelist={['*']}
        startInLoadingState
      />
      <Pressable
        onPress={openExternal}
        style={({ pressed }) => [
          styles.arButton,
          pressed && styles.arButtonPressed,
        ]}
        accessibilityLabel="Open Map in browser to enter AR"
      >
        <Text style={styles.arButtonText}>🥽 Open AR</Text>
      </Pressable>
    </View>
  );
}

const Tab = createBottomTabNavigator();

const screenOptions = ({
  route,
}: {
  route: { name: string };
}): BottomTabNavigationOptions => ({
  headerShown: false,
  tabBarActiveTintColor: '#ffffff',
  tabBarInactiveTintColor: '#888888',
  tabBarStyle: styles.tabBar,
  tabBarLabelStyle: styles.tabLabel,
  tabBarIcon: ({ color }) => (
    <Text style={[styles.tabIcon, { color }]}>
      {TAB_ICONS[route.name as TabName] ?? '•'}
    </Text>
  ),
});

const CustomersScreen = () => <WebViewScreen url={URLS.Customers} />;
const LedgerScreen = () => <WebViewScreen url={URLS.Ledger} />;
const InventoryScreen = () => <WebViewScreen url={URLS.Inventory} />;
const DashboardScreen = () => <WebViewScreen url={URLS.Dashboard} />;

function App() {
  return (
    <SafeAreaProvider>
      <StatusBar hidden />
      <NavigationContainer>
        <Tab.Navigator initialRouteName="Map" screenOptions={screenOptions}>
          <Tab.Screen name="Map" component={MapScreen} />
          <Tab.Screen name="Customers" component={CustomersScreen} />
          <Tab.Screen name="Ledger" component={LedgerScreen} />
          <Tab.Screen name="Inventory" component={InventoryScreen} />
          <Tab.Screen name="Dashboard" component={DashboardScreen} />
        </Tab.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: '#1a1a1a' },
  tabBar: {
    backgroundColor: '#1a1a1a',
    borderTopColor: '#1a1a1a',
  },
  tabLabel: {
    fontSize: 11,
  },
  tabIcon: {
    fontSize: 20,
  },
  arButton: {
    position: 'absolute',
    top: 16,
    right: 16,
    backgroundColor: '#1a73e8',
    paddingVertical: 10,
    paddingHorizontal: 16,
    borderRadius: 24,
    shadowColor: '#000',
    shadowOpacity: 0.4,
    shadowRadius: 6,
    shadowOffset: { width: 0, height: 2 },
    elevation: 6,
  },
  arButtonPressed: {
    backgroundColor: '#1456b8',
  },
  arButtonText: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '700',
  },
});

export default App;

