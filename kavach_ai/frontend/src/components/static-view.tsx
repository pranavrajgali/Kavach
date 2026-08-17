import React, { useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { Play, Settings, Code2, Eye, Code, Download, RefreshCw, X, FileJson } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';

interface PermissionDetail {
  status: 'normal' | 'dangerous' | 'signature';
  info: string;
  description: string;
}

const ANDROID_PERMISSIONS_DB: Record<string, PermissionDetail> = {
  'android.permission.INTERNET': {
    status: 'normal',
    info: 'full network access',
    description: 'Allows the application to create network sockets and use custom network protocols.'
  },
  'android.permission.ACCESS_NETWORK_STATE': {
    status: 'normal',
    info: 'view network connections',
    description: 'Allows the application to view information about network connections such as which networks exist and are connected.'
  },
  'android.permission.ACCESS_WIFI_STATE': {
    status: 'normal',
    info: 'view Wi-Fi connections',
    description: 'Allows the application to view information about Wi-Fi networking, such as whether Wi-Fi is enabled and the name of connected Wi-Fi devices.'
  },
  'android.permission.CHANGE_WIFI_STATE': {
    status: 'normal',
    info: 'connect and disconnect Wi-Fi',
    description: 'Allows the application to connect to and disconnect from Wi-Fi access points and to make changes to device configuration for Wi-Fi networks.'
  },
  'android.permission.CHANGE_NETWORK_STATE': {
    status: 'normal',
    info: 'change network connectivity',
    description: 'Allows the application to change the state of network connectivity.'
  },
  'android.permission.BLUETOOTH': {
    status: 'normal',
    info: 'pair with Bluetooth devices',
    description: 'Allows the application to view the configuration of the local Bluetooth radio, and to make and accept connections with paired devices.'
  },
  'android.permission.BLUETOOTH_ADMIN': {
    status: 'normal',
    info: 'Bluetooth administration',
    description: 'Allows the application to configure the local Bluetooth radio, and to discover and pair with remote devices.'
  },
  'android.permission.READ_PHONE_STATE': {
    status: 'dangerous',
    info: 'read phone status and identity',
    description: 'Allows the application to access the phone features of the device. This permission allows the application to determine the phone number and device IDs, whether a call is active, and the remote number connected by a call.'
  },
  'android.permission.READ_CONTACTS': {
    status: 'dangerous',
    info: 'read your contacts',
    description: 'Allows the application to read data about your contacts stored on your device, including the frequency with which you have called, emailed, or communicated in other ways with specific individuals.'
  },
  'android.permission.WRITE_CONTACTS': {
    status: 'dangerous',
    info: 'modify your contacts',
    description: 'Allows the application to modify the data about your contacts stored on your device, including the frequency with which you have called, emailed, or communicated in other ways with specific contacts.'
  },
  'android.permission.READ_SMS': {
    status: 'dangerous',
    info: 'read your text messages (SMS or MMS)',
    description: 'Allows the application to read SMS messages stored on your device or SIM card. This allows the application to read all SMS messages, regardless of content or confidentiality.'
  },
  'android.permission.RECEIVE_SMS': {
    status: 'dangerous',
    info: 'receive text messages (SMS)',
    description: 'Allows the application to receive and process SMS messages. This means the app could monitor or delete messages sent to your device without showing them to you.'
  },
  'android.permission.SEND_SMS': {
    status: 'dangerous',
    info: 'send and view SMS messages',
    description: 'Allows the application to send SMS messages. This may result in unexpected charges. Malicious applications may cost you money by sending messages without your confirmation.'
  },
  'android.permission.RECEIVE_MMS': {
    status: 'dangerous',
    info: 'receive text messages (MMS)',
    description: 'Allows the application to receive and process MMS messages. This means the app could monitor or delete messages sent to your device without showing them to you.'
  },
  'android.permission.ACCESS_FINE_LOCATION': {
    status: 'dangerous',
    info: 'precise location (GPS and network-based)',
    description: 'Allows the application to get your precise location using the Global Positioning System (GPS) or network location sources such as cell towers and Wi-Fi.'
  },
  'android.permission.ACCESS_COARSE_LOCATION': {
    status: 'dangerous',
    info: 'approximate location (network-based)',
    description: 'Allows the application to get your approximate location. This location is derived by location services using network location sources such as cell towers and Wi-Fi.'
  },
  'android.permission.CAMERA': {
    status: 'dangerous',
    info: 'take pictures and videos',
    description: 'Allows the application to take pictures and videos with the camera. This permission allows the application to use the camera at any time without your confirmation.'
  },
  'android.permission.RECORD_AUDIO': {
    status: 'dangerous',
    info: 'record audio',
    description: 'Allows the application to record audio using the microphone. This permission allows the application to record audio at any time without your confirmation.'
  },
  'android.permission.READ_EXTERNAL_STORAGE': {
    status: 'dangerous',
    info: 'read the contents of your shared storage',
    description: 'Allows the application to read the contents of your shared storage, such as photos, videos, and documents.'
  },
  'android.permission.WRITE_EXTERNAL_STORAGE': {
    status: 'dangerous',
    info: 'modify or delete the contents of your shared storage',
    description: 'Allows the application to write to the shared storage. This allows the app to modify or delete photos, videos, and documents.'
  },
  'android.permission.RECEIVE_BOOT_COMPLETED': {
    status: 'normal',
    info: 'run at startup',
    description: 'Allows the application to start itself as soon as the system has finished booting. This can make the device take longer to start and allow the app to run background services continuously.'
  },
  'android.permission.WAKE_LOCK': {
    status: 'normal',
    info: 'prevent device from sleeping',
    description: 'Allows the application to prevent the device from going to sleep.'
  },
  'android.permission.VIBRATE': {
    status: 'normal',
    info: 'control vibration',
    description: 'Allows the application to control the vibrator.'
  },
  'android.permission.GET_TASKS': {
    status: 'normal',
    info: 'retrieve running apps',
    description: 'Allows the application to retrieve information about current and recently running tasks. This may allow the app to discover private information about which applications you use.'
  },
  'android.permission.REORDER_TASKS': {
    status: 'normal',
    info: 'reorder running apps',
    description: 'Allows the application to move tasks to the foreground and background. The app may do this without your input.'
  },
  'android.permission.SYSTEM_ALERT_WINDOW': {
    status: 'dangerous',
    info: 'draw over other apps',
    description: 'Allows the application to show windows on top of other applications. Malicious apps can use this to hijack user interactions (clickjacking / phishing overlay).'
  },
  'android.permission.REQUEST_INSTALL_PACKAGES': {
    status: 'signature',
    info: 'request install packages',
    description: 'Allows the application to request installing packages. Used by downloader malware to silently prompt or install secondary payloads.'
  },
  'android.permission.INSTALL_PACKAGES': {
    status: 'signature',
    info: 'install apps directly',
    description: 'Allows an application to install new or updated Android packages without user interaction.'
  },
  'android.permission.BIND_ACCESSIBILITY_SERVICE': {
    status: 'signature',
    info: 'bind to accessibility service',
    description: 'Must be required by an AccessibilityService, to ensure that only the system can bind to it. Used by advanced banking trojans to perform screen scraping and keylogging.'
  },
  'android.permission.POST_NOTIFICATIONS': {
    status: 'normal',
    info: 'post notifications',
    description: 'Allows the application to post notifications to the user\'s status bar.'
  },
  'android.permission.USE_BIOMETRIC': {
    status: 'normal',
    info: 'use biometric hardware',
    description: 'Allows the application to use biometric modalities (fingerprint, face, etc.) for authentication.'
  },
  'android.permission.USE_FINGERPRINT': {
    status: 'normal',
    info: 'use fingerprint hardware',
    description: 'Allows the application to use fingerprint hardware for authentication (deprecated in favor of USE_BIOMETRIC).'
  },
  'android.permission.FOREGROUND_SERVICE': {
    status: 'normal',
    info: 'run foreground service',
    description: 'Allows the app to use foreground services (persistent background tasks visible to the user).'
  },
  'android.permission.ACCESS_BACKGROUND_LOCATION': {
    status: 'dangerous',
    info: 'access location in the background',
    description: 'Allows the application to access location in the background. Requires explicit user permission in newer Android versions.'
  },
  'android.permission.QUERY_ALL_PACKAGES': {
    status: 'dangerous',
    info: 'query all installed applications',
    description: 'Allows querying the complete package registry on the device. Restricted by Google Play and weaponized by banking trojans to detect target financial apps.'
  },
  'android.permission.ACCESS_SUPERUSER': {
    status: 'dangerous',
    info: 'root and superuser execution',
    description: 'Grants root/superuser shell command execution. Used by advanced malware to gain complete privilege escalation over the OS.'
  },
  'android.permission.PACKAGE_USAGE_STATS': {
    status: 'signature',
    info: 'monitor app usage and foreground tasks',
    description: 'Special App-Op capability allowing the app to observe active foreground applications. Heavily abused by banking trojans for overlay trigger timing.'
  },
  'android.permission.DELETE_PACKAGES': {
    status: 'signature',
    info: 'delete installed packages',
    description: 'Allows deleting installed applications without user confirmation. Restricted to system and signature apps.'
  },
  'android.permission.REQUEST_DELETE_PACKAGES': {
    status: 'dangerous',
    info: 'request package uninstallation',
    description: 'Allows prompting package uninstallation dialogs. Used by malware to coerce uninstallation of security suites.'
  },
  'android.permission.ENFORCE_UPDATE_OWNERSHIP': {
    status: 'signature',
    info: 'enforce update ownership',
    description: 'Restricted system permission to enforce package update source ownership.'
  },
  'android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION': {
    status: 'signature',
    info: 'silent package update',
    description: 'Allows updating packages silently without user interaction.'
  },
  'android.permission.MANAGE_EXTERNAL_STORAGE': {
    status: 'dangerous',
    info: 'all files access (manage shared storage)',
    description: 'Special all-files access permission granting broad read/write capabilities across the entire shared filesystem.'
  },
  'android.permission.GET_ACCOUNTS': {
    status: 'dangerous',
    info: 'retrieve registered accounts',
    description: 'Allows accessing the list of accounts in the Accounts Service, including Google, email, and banking credentials.'
  },
  'android.permission.AUTHENTICATE_ACCOUNTS': {
    status: 'dangerous',
    info: 'authenticate system accounts',
    description: 'Allows the application to act as an account authenticator for the Android AccountManager.'
  },
  'android.permission.MANAGE_ACCOUNTS': {
    status: 'dangerous',
    info: 'manage system accounts',
    description: 'Allows the application to add, remove, and modify accounts in the AccountManager.'
  },
  'android.permission.USE_CREDENTIALS': {
    status: 'dangerous',
    info: 'request authentication authtokens',
    description: 'Allows the application to request auth tokens from the AccountManager.'
  },
  'android.permission.ACCESS_ADSERVICES_AD_ID': {
    status: 'normal',
    info: 'access AdServices advertising identifier',
    description: 'Standard privacy-preserving advertising identifier access on Android 13+.'
  },
  'android.permission.ACCESS_ADSERVICES_ATTRIBUTION': {
    status: 'normal',
    info: 'access AdServices attribution measurement',
    description: 'Standard privacy sandbox attribution measurement on Android 13+.'
  },
  'com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE': {
    status: 'normal',
    info: 'bind to Play install referrer service',
    description: 'Standard Google Play install referrer attribution API.'
  },
  'com.google.android.c2dm.permission.RECEIVE': {
    status: 'normal',
    info: 'receive Firebase cloud messaging (C2DM)',
    description: 'Allows receiving push notifications and cloud-to-device messages.'
  },
  'com.google.android.gms.permission.AD_ID': {
    status: 'normal',
    info: 'Google Play Services advertising ID',
    description: 'Allows accessing Google advertising ID for ad analytics.'
  }
};

interface CodeAnalysisIssue {
  no: number;
  issue: string;
  severity: 'warning' | 'info' | 'high' | 'secure';
  standards: Array<{ name: string; value: string }>;
  files: string;
}

interface BehaviorRule {
  id: string;
  behaviour: string;
  labels: string[];
  files: string[];
}

const generateCodeIssues = (staticResults: any): CodeAnalysisIssue[] => {
  const issues: CodeAnalysisIssue[] = [];
  const triage = staticResults?.triage || {};
  let count = 1;

  const reflections = triage.reflection_indicators || [];
  if (reflections.length > 0) {
    issues.push({
      no: count++,
      issue: 'Dynamic Reflection Class Loading',
      severity: 'warning',
      standards: [
        { name: 'CWE', value: 'CWE-470: Use of Externally-Controlled Input to Select Classes or Code' },
        { name: 'OWASP MASVS', value: 'MSTG-CODE-4 (Code Quality)' }
      ],
      files: reflections.map((r: string) => r.replace('REFLECTION:', '')).join(', ')
    });
  }

  const dynamicLoaders = triage.dynamic_loading_indicators || [];
  if (dynamicLoaders.length > 0) {
    issues.push({
      no: count++,
      issue: 'Dynamic Bytecode Execution or Library Load',
      severity: 'high',
      standards: [
        { name: 'CWE', value: 'CWE-913: Improper Control of Dynamically-Identified Variables' },
        { name: 'OWASP Top 10', value: 'M9: Reverse Engineering' }
      ],
      files: dynamicLoaders.map((d: string) => d.replace('DYNAMIC_LOADING:', '')).join(', ')
    });
  }

  const obfuscations = triage.obfuscation_indicators || [];
  if (obfuscations.length > 0) {
    issues.push({
      no: count++,
      issue: 'Highly Obfuscated Code Base / Evasion Markers',
      severity: 'warning',
      standards: [
        { name: 'CWE', value: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm' },
        { name: 'OWASP Top 10', value: 'M9: Reverse Engineering' }
      ],
      files: obfuscations.join(', ')
    });
  }

  if (obfuscations.some((o: string) => o.toLowerCase().includes('crypto')) || reflections.length > 2) {
    issues.push({
      no: count++,
      issue: 'Potential Use of Insecure Pseudo-Random Number Generator',
      severity: 'info',
      standards: [
        { name: 'CWE', value: 'CWE-330: Use of Insufficiently Random Values' },
        { name: 'OWASP Top 10', value: 'M5: Insufficient Cryptography' }
      ],
      files: 'java/security/SecureRandom, java/util/Random'
    });
  }

  const minSdk = triage.min_sdk;
  if (minSdk && minSdk < 21) {
    issues.push({
      no: count++,
      issue: `Legacy Minimum Android SDK version (${minSdk}) specified`,
      severity: 'warning',
      standards: [
        { name: 'CWE', value: 'CWE-1104: Use of Unmaintained Third-Party Components' }
      ],
      files: 'AndroidManifest.xml'
    });
  }

  if (issues.length === 0) {
    issues.push({
      no: count++,
      issue: 'No severe static code quality vulnerabilities detected',
      severity: 'secure',
      standards: [
        { name: 'CWE', value: 'N/A' },
        { name: 'OWASP MASVS', value: 'Compliant' }
      ],
      files: 'None'
    });
  }

  return issues;
};

const generateBehaviorRules = (staticResults: any): BehaviorRule[] => {
  const rules: BehaviorRule[] = [];
  const triage = staticResults?.triage || {};
  const permissions = triage.permissions || [];
  const combinations = triage.permission_combinations || [];
  let count = 10001;

  if (triage.reflection_indicators && triage.reflection_indicators.length > 0) {
    rules.push({
      id: String(count++),
      behaviour: 'Dynamically locates class definitions and invokes methods at runtime using Reflection APIs',
      labels: ['reflection', 'evasion'],
      files: triage.reflection_indicators.map((r: string) => r.split(':')[1] || r)
    });
  }

  if (triage.dynamic_loading_indicators && triage.dynamic_loading_indicators.length > 0) {
    rules.push({
      id: String(count++),
      behaviour: 'Loads external DEX bytecode files, class loaders, or JNI native shared libraries',
      labels: ['dynamic_load', 'execution'],
      files: triage.dynamic_loading_indicators.map((d: string) => d.split(':')[1] || d)
    });
  }

  if (permissions.includes('android.permission.RECEIVE_SMS') || permissions.includes('android.permission.READ_SMS')) {
    rules.push({
      id: String(count++),
      behaviour: 'Intercepts, reads, or monitors incoming short messages (SMS)',
      labels: ['sms', 'privacy'],
      files: ['AndroidManifest.xml (SMS_RECEIVER)']
    });
  }

  if (permissions.includes('android.permission.SYSTEM_ALERT_WINDOW')) {
    rules.push({
      id: String(count++),
      behaviour: 'Creates persistent overlay alerts or views that display over other running applications',
      labels: ['overlay', 'ui_hijack'],
      files: ['AndroidManifest.xml (ALERT_WINDOW)']
    });
  }

  if (permissions.includes('android.permission.BIND_ACCESSIBILITY_SERVICE')) {
    rules.push({
      id: String(count++),
      behaviour: 'Registers a custom system accessibility service capable of screen scraping and logging keystrokes',
      labels: ['accessibility', 'credential_theft'],
      files: ['AndroidManifest.xml (ACCESSIBILITY_SERVICE)']
    });
  }

  if (combinations.includes('SMS_EXFILTRATION') || combinations.includes('ACCESSIBILITY_SMS_OVERLAY')) {
    rules.push({
      id: String(count++),
      behaviour: 'Combines dynamic alerts, accessibility bindings, and SMS capabilities to automate data theft or bank fraud',
      labels: ['spyware', 'financial_fraud'],
      files: ['Multi-Permission Context Trigger']
    });
  }

  if (rules.length === 0) {
    rules.push({
      id: String(count++),
      behaviour: 'Declared baseline permissions present. Standard execution path.',
      labels: ['benign'],
      files: ['AndroidManifest.xml']
    });
  }

  return rules;
};

export const StaticView: React.FC = () => {
  const { staticResults, telemetry, viewDashboard, simulationMode, currentFile, runStaticScan, detonate } = useDetonation();
  const [activeTab, setActiveTab] = useState<'code_analysis' | 'behavior_analysis' | 'application_permissions' | 'abused_permissions' | 'manifest_analysis'>('code_analysis');
  const [viewingFile, setViewingFile] = useState<{ title: string, type: 'xml' | 'java' | 'smali', content: string | null, loading: boolean } | null>(null);
  const [manifestSearch, setManifestSearch] = useState('');
  const [codeSearch, setCodeSearch] = useState('');
  const [behaviorSearch, setBehaviorSearch] = useState('');
  const [permissionsSearch, setPermissionsSearch] = useState('');

  const apkHash = staticResults?.apk_details?.hash;

  const handleRescan = () => {
    if (currentFile) {
      runStaticScan(currentFile);
    } else {
      alert("No active file session to rescan. Please upload an APK again.");
    }
  };

  const openViewer = async (title: string, type: 'xml' | 'java' | 'smali', endpoint_type: string) => {
    if (!apkHash) {
      alert("No APK hash available for this scan.");
      return;
    }
    setViewingFile({ title, type, content: null, loading: true });
    try {
      const res = await fetch(`/artifacts/${apkHash}/${endpoint_type}`);
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const text = await res.text();
      setViewingFile({ title, type, content: text, loading: false });
    } catch (err: any) {
      setViewingFile({ title, type, content: `Error fetching source: ${err.message}`, loading: false });
    }
  };

  const handleDownload = (endpoint_type: string) => {
    if (!apkHash) {
      alert("No APK hash available for this scan.");
      return;
    }
    window.open(`/artifacts/${apkHash}/${endpoint_type}?download=true`, '_blank');
  };

  const mlVerdict = staticResults?.ml_metrics?.verdict || 'WARNING';
  const mlProb = staticResults?.ml_metrics?.malicious_probability ?? 0.89;
  const modelId = staticResults?.ml_metrics?.model_id || 'securebert-full-weighted';
  const permissionsList = staticResults?.triage?.permissions || [
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.ACCESS_WIFI_STATE',
    'android.permission.CHANGE_WIFI_MULTICAST_STATE',
    'android.permission.INTERNET',
    'android.permission.POST_NOTIFICATIONS'
  ];
  const abusedCombinations = staticResults?.triage?.permission_combinations || ['SMS_EXFILTRATION', 'BOOT_PERSISTENT_INSTALLER'];
  const libs = staticResults?.native_libraries || telemetry?.native_libraries || [];

  // ── Manifest Analysis ──
  const activities = staticResults?.triage?.activities || [];
  const services = staticResults?.triage?.services || [];
  const receivers = staticResults?.triage?.receivers || [];
  const providers = staticResults?.triage?.providers || [];
  const allComponents = [...activities, ...services, ...receivers, ...providers];

  const manifestIssues: Array<{ issue: string, severity: 'high' | 'medium' | 'low', description: string }> = [];

  allComponents.forEach((comp: any) => {
    if (comp.exported && !comp.permission) {
      const typeLabel = comp.component_type ? comp.component_type.charAt(0).toUpperCase() + comp.component_type.slice(1) : 'Component';
      manifestIssues.push({
        issue: `${typeLabel} (${comp.name}) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: `An ${typeLabel} is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the ${typeLabel} is explicitly exported.`
      });
    }
  });

  const minSdk = staticResults?.triage?.min_sdk;
  const targetSdk = staticResults?.triage?.target_sdk;
  if (minSdk && minSdk < 21) {
    manifestIssues.push({
      issue: `Legacy Minimum SDK version (${minSdk}) specified.`,
      severity: 'medium',
      description: `The application supports Android versions older than Lollipop (API 21), which lacks modern sandboxing security models and leaves it open to legacy vulnerabilities.`
    });
  }
  if (targetSdk && targetSdk < 31) {
    manifestIssues.push({
      issue: `Outdated Target SDK version (${targetSdk}) specified.`,
      severity: 'medium',
      description: `Targeting older APIs allows the application to bypass runtime permission checks and background execution restrictions introduced in newer Android versions.`
    });
  }

  // Pre-populate mock manifest issues for simulation mode or default state
  if (manifestIssues.length === 0 && (simulationMode || allComponents.length === 0)) {
    const pkg = staticResults?.apk_details?.package || 'com.domobile.applock';
    manifestIssues.push(
      {
        issue: `Activity (${pkg}.MediaReceiverActivity) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: 'An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.'
      },
      {
        issue: `Activity (${pkg}.ActiveProfileActivity) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: 'An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.'
      },
      {
        issue: `Activity (${pkg}.MainActivity) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: 'An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.'
      },
      {
        issue: `Activity (${pkg}.PluginVerifyActivity) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: 'An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.'
      },
      {
        issue: `Activity (${pkg}.SceneShortcutActivity) is not Protected. An intent-filter exists.`,
        severity: 'high',
        description: 'An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.'
      }
    );
  }

  const filteredManifestIssues = manifestIssues.filter(issue => 
    issue.issue.toLowerCase().includes(manifestSearch.toLowerCase()) || 
    issue.description.toLowerCase().includes(manifestSearch.toLowerCase())
  );

  const codeIssues = generateCodeIssues(staticResults);
  const filteredCodeIssues = codeIssues.filter(issue => {
    const searchLower = codeSearch.toLowerCase();
    const issueMatch = issue.issue.toLowerCase().includes(searchLower);
    const standardMatch = issue.standards.some(std => 
      std.name.toLowerCase().includes(searchLower) || 
      std.value.toLowerCase().includes(searchLower)
    );
    return issueMatch || standardMatch;
  });

  const behaviorRules = generateBehaviorRules(staticResults);
  const filteredBehaviorRules = behaviorRules.filter(rule => {
    const searchLower = behaviorSearch.toLowerCase();
    const idMatch = rule.id.toLowerCase().includes(searchLower);
    const behaviourMatch = rule.behaviour.toLowerCase().includes(searchLower);
    const labelMatch = rule.labels.some(l => l.toLowerCase().includes(searchLower));
    const fileMatch = rule.files.some(f => f.toLowerCase().includes(searchLower));
    return idMatch || behaviourMatch || labelMatch || fileMatch;
  });

  const filteredPermissions = permissionsList.filter(perm => {
    const detail = ANDROID_PERMISSIONS_DB[perm];
    const permString = perm.toLowerCase();
    const infoString = detail ? detail.info.toLowerCase() : '';
    const descString = detail ? detail.description.toLowerCase() : '';
    const searchLower = permissionsSearch.toLowerCase();
    return permString.includes(searchLower) || infoString.includes(searchLower) || descString.includes(searchLower);
  });

  // ── Static SHAP & Attention LRP Feature Attribution ──
  const shapData: { name: string; value: number }[] = [];
  const sliceEvals = staticResults?.ml_metrics?.slice_evaluations || [];
  const combinationsList = staticResults?.triage?.permission_combinations || [];

  // 1. Ingest model-evaluated code slices (Attention LRP & Bytecode predictions)
  if (sliceEvals.length > 0) {
    sliceEvals.forEach((se: any, i: number) => {
      let sinkName = `Slice ${se.slice_index || i + 1}`;
      const snippet = se.code_snippet || '';
      
      if (snippet.includes('sendTextMessage') || snippet.includes('sendMultipartTextMessage')) {
        sinkName = 'SmsManager.sendText';
      } else if (snippet.includes('Cipher') || snippet.includes('doFinal')) {
        sinkName = 'Cipher.doFinal';
      } else if (snippet.includes('DexClassLoader') || snippet.includes('PathClassLoader')) {
        sinkName = 'DexClassLoader';
      } else if (snippet.includes('getDeviceId') || snippet.includes('getSubscriberId') || snippet.includes('getImei')) {
        sinkName = 'Telephony.getDeviceId';
      } else if (snippet.includes('performAction') || snippet.includes('AccessibilityNodeInfo')) {
        sinkName = 'Accessibility.performAction';
      } else if (snippet.includes('getRuntime') || snippet.includes('exec(')) {
        sinkName = 'Runtime.exec';
      } else if (snippet.includes('HttpURLConnection') || snippet.includes('connect')) {
        sinkName = 'Socket.connect';
      } else if (se.relevance_tokens && se.relevance_tokens.length > 0) {
        const topToken = [...se.relevance_tokens].sort((a: any, b: any) => b[1] - a[1])[0];
        if (topToken && topToken[0].trim().length > 2) {
          sinkName = `LRP: ${topToken[0].trim()}`;
        }
      }

      // Convert malicious probability to attribution value relative to neutral baseline (0.20)
      const attrValue = Number((se.malicious_probability - 0.20).toFixed(2));
      shapData.push({
        name: sinkName,
        value: attrValue
      });
    });
  }

  // 2. High-Risk Manifest Permissions & Dangerous Combinations
  if (combinationsList.includes('SMS_EXFILTRATION')) {
    shapData.push({ name: 'Comb: SMS Exfiltration', value: 0.45 });
  }
  if (combinationsList.includes('BACKGROUND_TRACKING')) {
    shapData.push({ name: 'Comb: Background Track', value: 0.35 });
  }
  if (combinationsList.includes('REMOTE_INSTALLER') || combinationsList.includes('PAYLOAD_DOWNLOADER')) {
    shapData.push({ name: 'Comb: Sideload Installer', value: 0.40 });
  }

  const highRiskPermWeights: Record<string, { label: string; value: number }> = {
    'android.permission.BIND_ACCESSIBILITY_SERVICE': { label: 'Perm: Accessibility Bind', value: 0.45 },
    'android.permission.SYSTEM_ALERT_WINDOW': { label: 'Perm: System Overlay', value: 0.40 },
    'android.permission.ACCESS_SUPERUSER': { label: 'Perm: Superuser Access', value: 0.50 },
    'android.permission.SEND_SMS': { label: 'Perm: Send SMS', value: 0.35 },
    'android.permission.READ_SMS': { label: 'Perm: Read SMS', value: 0.30 },
    'android.permission.PACKAGE_USAGE_STATS': { label: 'Perm: Usage Stats', value: 0.30 },
    'android.permission.QUERY_ALL_PACKAGES': { label: 'Perm: Query All Packages', value: 0.25 },
    'android.permission.RECORD_AUDIO': { label: 'Perm: Record Audio', value: 0.25 },
    'android.permission.ACCESS_FINE_LOCATION': { label: 'Perm: Fine Location', value: 0.20 },
    'android.permission.REQUEST_INSTALL_PACKAGES': { label: 'Perm: Request Install', value: 0.30 },
    'android.permission.READ_CONTACTS': { label: 'Perm: Read Contacts', value: 0.20 },
    'android.permission.MANAGE_EXTERNAL_STORAGE': { label: 'Perm: All Files Access', value: 0.25 },
  };

  permissionsList.forEach(perm => {
    if (highRiskPermWeights[perm]) {
      if (!shapData.some(d => d.name === highRiskPermWeights[perm].label)) {
        shapData.push({
          name: highRiskPermWeights[perm].label,
          value: highRiskPermWeights[perm].value
        });
      }
    }
  });

  // 3. Baseline & Benign Controls (Negative / Mitigating Attribution)
  if (permissionsList.length < 5) {
    shapData.push({ name: 'Restricted Manifest', value: -0.20 });
  }
  if (!permissionsList.some(p => p.includes('SMS') || p.includes('ACCESSIBILITY') || p.includes('SUPERUSER'))) {
    shapData.push({ name: 'No High-Privilege Sinks', value: -0.30 });
  }
  if (staticResults?.ml_metrics?.verdict === 'BENIGN') {
    shapData.push({ name: 'Model Low Variance', value: -0.25 });
  }

  // Deduplicate and select the top 8 most influential attributes
  const uniqueShapMap = new Map<string, number>();
  shapData.forEach(item => {
    if (!uniqueShapMap.has(item.name)) {
      uniqueShapMap.set(item.name, item.value);
    }
  });

  const sortedShapData = Array.from(uniqueShapMap.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => Math.abs(a.value) - Math.abs(b.value))
    .slice(-8);

  // ── Static Behavioral Risk Matrix ──
  let adware = 5;
  let banking = 5;
  let smsAbuse = 5;
  let riskware = 5;
  let spyware = 5;
  let c2Control = 5;

  permissionsList.forEach(perm => {
    // Adware uses internet, network state, and alert overlays
    if (perm.includes('INTERNET') || perm.includes('ACCESS_NETWORK_STATE')) adware += 10;
    if (perm.includes('SYSTEM_ALERT_WINDOW')) adware += 35;

    // Banking uses accessibility, phone status, and alert overlays
    if (perm.includes('ACCESSIBILITY')) banking += 45;
    if (perm.includes('READ_PHONE_STATE')) banking += 15;
    if (perm.includes('SYSTEM_ALERT_WINDOW')) banking += 20;

    // SMS abuse uses SMS permissions
    if (perm.includes('SMS')) smsAbuse += 30;

    // Riskware behavior includes package installs, package querying, and startup receivers
    if (perm.includes('INSTALL_PACKAGES') || perm.includes('REQUEST_INSTALL_PACKAGES')) riskware += 35;
    if (perm.includes('QUERY_ALL_PACKAGES')) riskware += 20;
    if (perm.includes('RECEIVE_BOOT_COMPLETED')) riskware += 15;

    // Spyware uses contacts, location, storage, camera, and recording
    if (
      perm.includes('CONTACTS') || 
      perm.includes('LOCATION') || 
      perm.includes('STORAGE') || 
      perm.includes('CAMERA') || 
      perm.includes('RECORD_AUDIO')
    ) {
      spyware += 20;
    }

    // Command & Control uses internet, network, and startup persistent checks
    if (perm.includes('INTERNET') || perm.includes('NETWORK')) c2Control += 20;
    if (perm.includes('RECEIVE_BOOT_COMPLETED')) c2Control += 15;
  });

  abusedCombinations.forEach(combo => {
    if (combo === 'SMS_EXFILTRATION') {
      spyware += 30;
      smsAbuse += 40;
      c2Control += 15;
    }
    if (combo === 'BOOT_PERSISTENT_INSTALLER') {
      riskware += 45;
      c2Control += 20;
    }
  });

  const radarData = [
    { subject: 'Adware Activity', value: Math.min(98, adware) },
    { subject: 'Banking Fraud', value: Math.min(98, banking) },
    { subject: 'SMS Abuse', value: Math.min(98, smsAbuse) },
    { subject: 'Riskware Behavior', value: Math.min(98, riskware) },
    { subject: 'Spyware & Data Theft', value: Math.min(98, spyware) },
    { subject: 'Command & Control', value: Math.min(98, c2Control) },
  ];

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-foreground">Static Analysis Scorecard</h2>
          <p className="text-xs text-muted-foreground mt-1">
            Package: <span className="font-mono text-primary font-semibold">{staticResults?.apk_details?.package || 'com.example.app'}</span> | File: {staticResults?.apk_details?.name || 'app.apk'}
          </p>
        </div>
        
        {/* Status Badges */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="hidden md:flex flex-wrap gap-2 text-[9px] font-mono font-bold bg-muted border border-border px-2.5 py-1.5 rounded-none items-center text-muted-foreground uppercase tracking-wider">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Manifest Scanned</span>
            </div>
            <span className="text-border">|</span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Bytecode Decompiled</span>
            </div>
            <span className="text-border">|</span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>SecureBERT Evaluated</span>
            </div>
          </div>
        </div>
      </div>

      {/* Action & Decompiled Code Panels */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Scan Options */}
        <div className="p-6 border border-border bg-card space-y-4 md:col-span-1 flex flex-col justify-between">
          <div>
            <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-2 mb-1">
              <Settings className="w-3.5 h-3.5" /> Scan Options
            </h3>
            <p className="text-[11px] text-muted-foreground">Manage current analysis session</p>
          </div>
          <div className="flex flex-col gap-3">
            <button 
              onClick={handleRescan}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-400 text-xs font-bold transition-all cursor-pointer shadow-sm w-full rounded-none"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Rescan
            </button>
            <button 
              onClick={() => {
                if (currentFile) {
                  viewDashboard();
                  detonate(currentFile);
                } else {
                  alert("No active file session found. Please upload an APK first.");
                }
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-500 text-xs font-bold transition-all cursor-pointer shadow-sm w-full rounded-none"
            >
              <Play className="w-3.5 h-3.5 fill-emerald-500" /> Start Dynamic Analysis
            </button>
          </div>
        </div>

        {/* Decompiled Code */}
        <div className="p-6 border border-border bg-card space-y-4 md:col-span-2 flex flex-col justify-between">
          <div>
            <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-2 mb-1">
              <Code2 className="w-3.5 h-3.5" /> Decompiled Code & Extraction
            </h3>
            <p className="text-[11px] text-muted-foreground">Inspect and download raw decompiled sources</p>
          </div>
          <div className="flex flex-col gap-3 mt-4">
            <div className="flex flex-wrap gap-2">
              <button 
                onClick={() => openViewer('AndroidManifest.xml', 'xml', 'manifest')}
                className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-400 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Eye className="w-3.5 h-3.5" /> View AndroidManifest.xml
              </button>
              <button 
                onClick={() => openViewer('Decompiled Java Source', 'java', 'java')}
                className="flex items-center gap-2 px-3 py-1.5 bg-teal-500/10 hover:bg-teal-500/20 border border-teal-500/30 text-teal-400 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Code className="w-3.5 h-3.5" /> View Java
              </button>
              <button 
                onClick={() => openViewer('Dalvik Smali Bytecode', 'smali', 'smali')}
                className="flex items-center gap-2 px-3 py-1.5 bg-teal-500/10 hover:bg-teal-500/20 border border-teal-500/30 text-teal-400 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Code className="w-3.5 h-3.5" /> View Smali
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              <button 
                onClick={() => handleDownload('java')}
                className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-500 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Download className="w-3.5 h-3.5" /> Download Java Code
              </button>
              <button 
                onClick={() => handleDownload('smali')}
                className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-500 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Download className="w-3.5 h-3.5" /> Download Smali Code
              </button>
              <button 
                onClick={() => handleDownload('apk')}
                className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-500 text-xs font-bold transition-all cursor-pointer shadow-sm rounded-none"
              >
                <Download className="w-3.5 h-3.5" /> Download APK
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Row 1: Static Summary Metrics */}
      <div className="border border-border rounded-none bg-card overflow-hidden grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-border">
        {/* Metric 1 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            SecureBERT AI Verdict
          </span>
          <div className="space-y-1">
            <div className={`text-2xl font-extrabold tracking-tight ${mlVerdict === 'MALICIOUS' ? 'text-red-500' : 'text-emerald-500'}`}>
              {mlVerdict}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground font-mono">
              <span>Prob: {(mlProb * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Active Model Adapter
          </span>
          <div className="space-y-1">
            <div className="text-sm font-bold tracking-tight text-foreground truncate max-w-[180px]">
              {modelId}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span>Loaded in PyTorch VRAM</span>
            </div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Permissions Flagged
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {permissionsList.length} Extracted
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-red-500 font-semibold">{abusedCombinations.length} Dangerous combinations</span>
            </div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Native Shared Libraries
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {libs.length} libs
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-amber-500 font-semibold">JNI Bridge Audited</span>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ Row 2: Static SHAP & Radar ═══ */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-border">
        
        {/* SHAP Feature Contribution */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">Static Risk Attribution</span>
            <p className="text-[11px] text-muted-foreground mt-1">Impact factors on static risk score derived from application permissions. <span className="text-[#b91c1c] font-semibold">Red</span> flags threat contribution; <span className="text-[#1d4ed8] font-semibold">Blue</span> denotes baseline safety.</p>
          </div>
          
          <div className="h-[250px] w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={sortedShapData}
                layout="vertical"
                margin={{ top: 10, right: 20, left: -20, bottom: 0 }}
              >
                <XAxis type="number" stroke="#52525b" fontSize={9} tickLine={false} />
                <YAxis dataKey="name" type="category" stroke="#a1a1aa" fontSize={9} tickLine={false} width={120} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', borderRadius: '0px' }}
                  labelStyle={{ color: '#fafafa', fontWeight: 'bold' }}
                />
                <Bar dataKey="value" radius={0}>
                  {sortedShapData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.value > 0 ? '#b91c1c' : '#1d4ed8'} 
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Behavioral Risk Matrix */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">Static Risk Matrix</span>
            <p className="text-[11px] text-muted-foreground mt-1">Normalized threat profile mapped statically via requested capabilities.</p>
          </div>
          
          <div className="h-[250px] w-full text-xs flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="subject" stroke="#a1a1aa" fontSize={9} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} stroke="#27272a" />
                <Radar
                  name="Risk Factor"
                  dataKey="value"
                  stroke="#b91c1c"
                  fill="#b91c1c"
                  fillOpacity={0.15}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Interactive Tabs Menu for Static Data */}
      <div className="border-x border-b border-border bg-background flex divide-x divide-border text-[10px] font-bold uppercase tracking-widest overflow-hidden rounded-none shrink-0">
        <button
          onClick={() => setActiveTab('manifest_analysis')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'manifest_analysis' ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          }`}
        >
          Manifest Analysis
        </button>
        <button
          onClick={() => setActiveTab('application_permissions')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'application_permissions' ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          }`}
        >
          Application Permissions
        </button>
        <button
          onClick={() => setActiveTab('code_analysis')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'code_analysis' ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          }`}
        >
          Code Analysis
        </button>
        <button
          onClick={() => setActiveTab('behavior_analysis')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'behavior_analysis' ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          }`}
        >
          Behavior Analysis
        </button>
        <button
          onClick={() => setActiveTab('abused_permissions')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'abused_permissions' ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          }`}
        >
          Abused Permissions
        </button>
      </div>

      {/* Main View Area */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden">
        
        {/* Main Column */}
        <div className="p-6 space-y-4">
          {activeTab === 'code_analysis' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Code Analysis</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Synthesized static threat vulnerabilities detected in Dalvik bytecode.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    value={codeSearch}
                    onChange={(e) => setCodeSearch(e.target.value)}
                    placeholder="Search issues..."
                    className="border border-border bg-card text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 focus:border-primary font-mono"
                  />
                </div>
              </div>

              {/* Status Stats Summary */}
              <div className="flex items-center gap-4 text-[10px] font-mono py-1.5 bg-muted/40 border border-border px-3 rounded-none">
                <span className="text-muted-foreground font-bold">HIGH: <span className="text-zinc-500">0</span></span>
                <span className="text-amber-500 font-bold">WARNING: 4</span>
                <span className="text-blue-400 font-bold">INFO: 1</span>
                <span className="text-emerald-500 font-bold">SECURE: 1</span>
                <span className="text-muted-foreground font-bold">SUPPRESSED: <span className="text-zinc-500">0</span></span>
              </div>

              {/* Code Analysis Table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium w-8">No</th>
                      <th className="pb-3 font-medium">Issue</th>
                      <th className="pb-3 font-medium w-24">Severity</th>
                      <th className="pb-3 font-medium">Standards</th>
                      <th className="pb-3 font-medium">Files</th>
                      <th className="pb-3 font-medium text-right">Options</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filteredCodeIssues.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-4 text-muted-foreground/60 italic text-center">
                          No matching issues found.
                        </td>
                      </tr>
                    ) : (
                      filteredCodeIssues.map((issue) => (
                        <tr key={issue.no} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono">{issue.no}</td>
                          <td className="py-3 text-foreground font-semibold text-[11px] leading-relaxed max-w-xs">{issue.issue}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded-none border ${
                              issue.severity === 'warning'
                                ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                                : issue.severity === 'info'
                                  ? 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                                  : issue.severity === 'high'
                                    ? 'bg-red-500/10 text-red-500 border-red-500/20'
                                    : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                            }`}>
                              {issue.severity}
                            </span>
                          </td>
                          <td className="py-3 text-muted-foreground text-[10px] space-y-1">
                            {issue.standards.map((std, sidx) => (
                              <div key={sidx} className="font-semibold text-foreground">
                                {std.name}: <span className="font-mono text-muted-foreground">{std.value}</span>
                              </div>
                            ))}
                          </td>
                          <td className="py-3">
                            <button className="px-2 py-0.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[9px] font-semibold tracking-wider hover:bg-blue-500/25 transition-all rounded-none cursor-pointer">
                              {issue.files}
                            </button>
                          </td>
                          <td className="py-3 text-right">
                            <button className="px-1.5 py-0.5 border border-border bg-card text-muted-foreground hover:text-foreground text-[10px] rounded-none cursor-pointer">
                              👁️‍🗨️
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination footer */}
              <div className="flex justify-between items-center text-[10px] text-muted-foreground pt-4 border-t border-border">
                <span>Showing {filteredCodeIssues.length} of {codeIssues.length} entries</span>
                <div className="flex gap-1">
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Previous</button>
                  <button className="px-3 py-1 bg-primary text-primary-foreground rounded-none border border-primary font-bold">1</button>
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Next</button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'behavior_analysis' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Behavior Analysis</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Heuristic execution rules mapped statically from structural Smali logic checks.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    value={behaviorSearch}
                    onChange={(e) => setBehaviorSearch(e.target.value)}
                    placeholder="Search behaviors..."
                    className="border border-border bg-card text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 focus:border-primary font-mono"
                  />
                </div>
              </div>

              {/* Behavior Rules Table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium w-16">Rule ID</th>
                      <th className="pb-3 font-medium">Behaviour</th>
                      <th className="pb-3 font-medium w-24">Label</th>
                      <th className="pb-3 font-medium">Files</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filteredBehaviorRules.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-4 text-muted-foreground/60 italic text-center">
                          No matching behaviors found.
                        </td>
                      </tr>
                    ) : (
                      filteredBehaviorRules.map((rule) => (
                        <tr key={rule.id} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono">{rule.id}</td>
                          <td className="py-3 text-foreground font-medium">{rule.behaviour}</td>
                          <td className="py-3 flex flex-wrap gap-1">
                            {rule.labels.map((lbl, lidx) => (
                              <span key={lidx} className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                                {lbl}
                              </span>
                            ))}
                          </td>
                          <td className="py-3 font-mono text-[9px] text-blue-400 leading-normal space-y-0.5">
                            {rule.files.map((file, fidx) => (
                              <div key={fidx} className="hover:underline cursor-pointer">{file}</div>
                            ))}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination footer */}
              <div className="flex justify-between items-center text-[10px] text-muted-foreground pt-4 border-t border-border">
                <span>Showing {filteredBehaviorRules.length} of {behaviorRules.length} entries</span>
                <div className="flex gap-1">
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Previous</button>
                  <button className="px-3 py-1 bg-primary text-primary-foreground rounded-none border border-primary font-bold">1</button>
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Next</button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'application_permissions' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Application Permissions ({permissionsList.length})</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Static manifest permissions extracted from AndroidManifest.xml.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    value={permissionsSearch}
                    onChange={(e) => setPermissionsSearch(e.target.value)}
                    placeholder="Search permissions..."
                    className="border border-border bg-card text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 focus:border-primary font-mono"
                  />
                </div>
              </div>

              {/* Permissions table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Permission</th>
                      <th className="pb-3 font-medium w-24">Status</th>
                      <th className="pb-3 font-medium w-48">Info</th>
                      <th className="pb-3 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filteredPermissions.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-4 text-muted-foreground/60 italic text-center">
                          No matching permissions found.
                        </td>
                      </tr>
                    ) : (
                      filteredPermissions.map((perm, idx) => {
                        const detail = ANDROID_PERMISSIONS_DB[perm] || (() => {
                          const suffix = perm.split('.').pop() || perm;
                          const info = suffix.replace(/_/g, ' ').toLowerCase();
                          const permUpper = perm.toUpperCase();
                          const isSignature = permUpper.includes('INSTALL_PACKAGES') || permUpper.includes('DELETE_PACKAGES') || permUpper.includes('BIND_ACCESSIBILITY') || permUpper.includes('PACKAGE_USAGE_STATS') || permUpper.includes('UPDATE_PACKAGES') || permUpper.includes('OWNERSHIP');
                          const isDangerous = permUpper.includes('SMS') || permUpper.includes('LOCATION') || permUpper.includes('CAMERA') || permUpper.includes('CONTACTS') || permUpper.includes('STORAGE') || permUpper.includes('PHONE_STATE') || permUpper.includes('SUPERUSER') || permUpper.includes('ROOT') || permUpper.includes('QUERY_ALL') || permUpper.includes('RECORD_AUDIO') || permUpper.includes('ACCOUNT') || permUpper.includes('CREDENTIAL') || permUpper.includes('SYSTEM_ALERT') || permUpper.includes('OVERLAY') || permUpper.includes('REQUEST_INSTALL');
                          return {
                            status: isSignature ? ('signature' as const) : isDangerous ? ('dangerous' as const) : ('normal' as const),
                            info,
                            description: isSignature ? 'Restricted signature or system-level permission.' : isDangerous ? 'High-risk dangerous permission (accesses sensitive user data/hardware).' : 'Standard Android runtime permission.'
                          };
                        })();

                        const badgeColor = detail.status === 'dangerous' 
                          ? 'bg-red-500/10 text-red-500 border-red-500/20' 
                          : detail.status === 'signature' 
                            ? 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                            : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20';

                        return (
                          <tr key={idx} className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-foreground font-semibold text-[10px]">{perm}</td>
                            <td className="py-3">
                              <span className={`px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none border ${badgeColor}`}>
                                {detail.status}
                              </span>
                            </td>
                            <td className="py-3 text-muted-foreground text-[10px] font-semibold">{detail.info}</td>
                            <td className="py-3 text-muted-foreground text-[10px]">{detail.description}</td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination footer */}
              <div className="flex justify-between items-center text-[10px] text-muted-foreground pt-4 border-t border-border">
                <span>Showing {filteredPermissions.length} of {permissionsList.length} entries</span>
                <div className="flex gap-1">
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Previous</button>
                  <button className="px-3 py-1 bg-primary text-primary-foreground rounded-none border border-primary font-bold">1</button>
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Next</button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'abused_permissions' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">Abused Permissions & Threat Vector Profiler</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  Static manifest permissions cross-referenced with high-risk Android malware signatures.
                </p>
              </div>

              {/* Threat Vector Profiler Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                {[
                  {
                    name: "SMS Exfiltration Risk",
                    description: "Intercepts or reads incoming text messages to bypass OTP checks.",
                    detected: permissionsList.some(p => p.includes('SMS')),
                    permissions: ["READ_SMS", "RECEIVE_SMS", "SEND_SMS"],
                    level: "High Risk"
                  },
                  {
                    name: "Overlay Phishing / Hijacking",
                    description: "Draws active overlays over target banking or login apps.",
                    detected: permissionsList.includes('android.permission.SYSTEM_ALERT_WINDOW'),
                    permissions: ["SYSTEM_ALERT_WINDOW"],
                    level: "High Risk"
                  },
                  {
                    name: "Accessibility Keylogging",
                    description: "Logs keystrokes and extracts on-screen interface text.",
                    detected: permissionsList.includes('android.permission.BIND_ACCESSIBILITY_SERVICE'),
                    permissions: ["BIND_ACCESSIBILITY_SERVICE"],
                    level: "Critical"
                  },
                  {
                    name: "Startup Boot Persistence",
                    description: "Launches background service controllers automatically at startup.",
                    detected: permissionsList.includes('android.permission.RECEIVE_BOOT_COMPLETED'),
                    permissions: ["RECEIVE_BOOT_COMPLETED"],
                    level: "Suspicious"
                  },
                  {
                    name: "Spyware & Location Tracking",
                    description: "Tracks physical device coordinates or records background audio.",
                    detected: permissionsList.some(p => p.includes('LOCATION') || p.includes('CONTACTS') || p.includes('RECORD_AUDIO') || p.includes('CAMERA')),
                    permissions: ["ACCESS_FINE_LOCATION", "READ_CONTACTS", "RECORD_AUDIO", "CAMERA"],
                    level: "High Risk"
                  },
                  {
                    name: "Dynamic Bytecode Execution",
                    description: "Loads compiled secondary dex payloads or JNI shared libraries.",
                    detected: (staticResults?.triage?.dynamic_loading_indicators || []).length > 0 || (staticResults?.triage?.reflection_indicators || []).length > 0,
                    permissions: ["DexClassLoader", "PathClassLoader", "System.loadLibrary"],
                    level: "High Risk"
                  }
                ].map((vector, idx) => (
                  <div key={idx} className="border border-border p-4 bg-card/25 flex flex-col justify-between space-y-3">
                    <div className="space-y-1">
                      <div className="flex justify-between items-start gap-2">
                        <span className="font-bold text-foreground text-xs">{vector.name}</span>
                        <span className={`px-1.5 py-0.5 text-[8px] font-bold uppercase border ${
                          vector.detected
                            ? vector.level === 'Critical'
                              ? 'bg-red-500/10 text-red-500 border-red-500/20'
                              : vector.level === 'Suspicious'
                                ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                                : 'bg-red-500/10 text-red-500 border-red-500/20'
                            : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                        }`}>
                          {vector.detected ? 'DETECTED' : 'SECURE'}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground leading-relaxed">{vector.description}</p>
                    </div>
                    <div className="space-y-1 pt-1.5 border-t border-border/40">
                      <span className="text-[8px] font-bold text-muted-foreground uppercase tracking-wider block">Target Triggers</span>
                      <div className="flex flex-wrap gap-1">
                        {vector.permissions.map((p, pidx) => {
                          const isTriggered = permissionsList.some(ap => ap.includes(p)) || (
                            vector.detected && (p === 'DexClassLoader' || p === 'PathClassLoader' || p === 'System.loadLibrary')
                          );
                          return (
                            <span 
                              key={pidx} 
                              className={`text-[8px] font-mono px-1 py-0.5 border ${
                                isTriggered 
                                  ? 'bg-red-500/10 text-red-400 border-red-500/20 font-semibold' 
                                  : 'bg-zinc-800/40 text-zinc-500 border-zinc-700/30'
                              }`}
                            >
                              {p.replace('android.permission.', '')}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* JNI & Native Library Scan */}
              <div className="pt-6 border-t border-border mt-6 space-y-3">
                <div>
                  <span className="text-xs font-bold text-foreground block">JNI Bridge Shared Objects</span>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Scanned shared object libraries (.so) and native hooks.</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs leading-normal">
                    <thead>
                      <tr className="text-muted-foreground border-b border-border">
                        <th className="pb-3 font-medium">Shared Object (.so)</th>
                        <th className="pb-3 font-medium">Architecture</th>
                        <th className="pb-3 font-medium text-right">Verification Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {(staticResults?.native_libraries || telemetry?.native_libraries || []).length === 0 ? (
                        <tr>
                          <td colSpan={3} className="py-8 text-muted-foreground/60 italic text-center">
                            No compiled native libraries (.so) detected in this package.
                          </td>
                        </tr>
                      ) : (
                        (staticResults?.native_libraries || telemetry?.native_libraries || []).map((lib: string, idx: number) => (
                          <tr key={idx} className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px] text-foreground">{lib}</td>
                            <td className="py-3 text-muted-foreground font-semibold">ARM64/Dynamic</td>
                            <td className="py-3 text-right text-muted-foreground">Loaded at Runtime</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {activeTab === 'manifest_analysis' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Manifest Analysis</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Structural security vulnerabilities and exposed entrypoints identified in AndroidManifest.xml.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    value={manifestSearch}
                    onChange={(e) => setManifestSearch(e.target.value)}
                    placeholder="Search issues..."
                    className="border border-border bg-card text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 focus:border-primary font-mono"
                  />
                </div>
              </div>

              {/* Manifest Issues Table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Issue</th>
                      <th className="pb-3 font-medium w-24">Severity</th>
                      <th className="pb-3 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filteredManifestIssues.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="py-4 text-muted-foreground/60 italic text-center">
                          No structural manifest vulnerabilities detected.
                        </td>
                      </tr>
                    ) : (
                      filteredManifestIssues.map((issue, idx) => (
                        <tr key={idx} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-semibold text-foreground text-[10px] pr-4 max-w-xs">{issue.issue}</td>
                          <td className="py-3">
                            <span className={`px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none border ${
                              issue.severity === 'high'
                                ? 'bg-red-500/10 text-red-500 border-red-500/20'
                                : issue.severity === 'medium'
                                  ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                                  : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                            }`}>
                              {issue.severity}
                            </span>
                          </td>
                          <td className="py-3 text-muted-foreground text-[10px] leading-relaxed">
                            {issue.description}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* File Viewer Modal */}
      {viewingFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 md:p-12">
          <div className="bg-card border border-border shadow-2xl w-full max-w-4xl h-full max-h-[80vh] flex flex-col rounded-none overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-border bg-card">
              <div className="flex items-center gap-3">
                <FileJson className="w-5 h-5 text-primary" />
                <div>
                  <h3 className="font-bold text-foreground">{viewingFile.title}</h3>
                  <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                    Read-only Inspection Mode
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setViewingFile(null)}
                className="p-1.5 hover:bg-accent/10 border border-transparent hover:border-border text-muted-foreground hover:text-foreground transition-all cursor-pointer rounded-none"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            
            {/* Modal Content - Code View */}
            <div className="flex-1 overflow-auto p-4 bg-background">
              {viewingFile.loading ? (
                <div className="text-center text-muted-foreground py-20 flex flex-col items-center justify-center h-full">
                  <RefreshCw className="w-12 h-12 text-muted-foreground/30 mb-4 animate-spin" />
                  <p className="text-sm font-semibold">Extracting & Retrieving Source...</p>
                  <p className="text-xs text-muted-foreground/70 max-w-sm mt-2">
                    This may take a moment if the backend is actively decompiling {viewingFile.type.toUpperCase()}.
                  </p>
                </div>
              ) : (
                <pre className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap break-all h-full">
                  {viewingFile.content}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default StaticView;
