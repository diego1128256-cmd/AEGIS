'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { setApiKey, setJwtToken, api } from '@/lib/api';
import { forwardRef } from 'react';
import {
  User, Mail, Lock, KeyRound, ChevronRight, ChevronLeft,
  Cpu, Globe, Wifi, Server, Monitor, Plus, Trash2,
  Bell, Send, Webhook, Check, ArrowRight, Search, Loader2,
  ShieldCheck, X, AlertTriangle, Database, Container, Shield,
  Laptop, Bot,
} from 'lucide-react';

/* ──────────────────────────────────────────────
   Types
   ────────────────────────────────────────────── */

type AuthMethod = 'register' | 'apikey';
type AIProvider = 'openrouter' | 'anthropic' | 'openai' | 'ollama' | 'skip';
type AssetMode = 'auto' | 'manual';

interface DiscoveredAsset {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: number[];
  status: string;
  selected: boolean;
  service_name?: string;
  version?: string;
  risk_score?: number;
}

interface ManualAsset {
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: string;
}

interface SetupState {
  // Step 1
  authMethod: AuthMethod;
  name: string;
  email: string;
  password: string;
  apiKey: string;
  loginMode: boolean;
  // Step 2
  aiProvider: AIProvider;
  aiProviderKey: string;
  ollamaUrl: string;
  // Step 3
  assetMode: AssetMode;
  scanTarget: string;
  scanConsent: boolean;
  discoveredAssets: DiscoveredAsset[];
  manualAssets: ManualAsset[];
  // Step 4
  webhookEnabled: boolean;
  webhookUrl: string;
  telegramEnabled: boolean;
  telegramBotToken: string;
  telegramChatId: string;
}

// Track which steps have been completed (visited and submitted)
type CompletedSteps = Record<number, boolean>;

const STEPS = [
  { id: 1, label: 'Account' },
  { id: 2, label: 'AI Provider' },
  { id: 3, label: 'Assets' },
  { id: 4, label: 'Alerts' },
  { id: 5, label: 'Ready' },
];

const AI_PROVIDERS: { id: AIProvider; label: string; description: string; icon: typeof Cpu }[] = [
  { id: 'openrouter', label: 'OpenRouter', description: 'Access 100+ models via one API key', icon: Globe },
  { id: 'anthropic', label: 'Anthropic', description: 'Claude models directly', icon: Cpu },
  { id: 'openai', label: 'OpenAI', description: 'GPT-4, GPT-3.5 and more', icon: Cpu },
  { id: 'ollama', label: 'Ollama', description: 'Self-hosted local models', icon: Server },
  { id: 'skip', label: 'Skip for now', description: 'Configure AI later in settings', icon: ChevronRight },
];

const ASSET_TYPES = [
  { value: 'web_application', label: 'Web Application', icon: Globe },
  { value: 'api_server', label: 'API Server', icon: Server },
  { value: 'database', label: 'Database', icon: Database },
  { value: 'server', label: 'Server', icon: Monitor },
  { value: 'workstation', label: 'Workstation', icon: Laptop },
  { value: 'ai_service', label: 'AI Service', icon: Bot },
  { value: 'container_platform', label: 'Container Platform', icon: Container },
  { value: 'security_tools', label: 'Security Tools', icon: Shield },
];

function getAssetIcon(type: string) {
  const found = ASSET_TYPES.find(t => t.value === type);
  return found ? found.icon : Monitor;
}

function getRiskColor(score: number | undefined) {
  if (!score || score <= 3) return 'text-[#22C55E]';
  if (score <= 6) return 'text-[#F59E0B]';
  return 'text-[#EF4444]';
}

function getRiskLabel(score: number | undefined) {
  if (!score || score <= 3) return 'Low';
  if (score <= 6) return 'Medium';
  return 'High';
}

/* ──────────────────────────────────────────────
   Component
   ────────────────────────────────────────────── */

export default function SetupWizard() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [mounted, setMounted] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [stepTransition, setStepTransition] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<CompletedSteps>({});
  const [manualForm, setManualForm] = useState<ManualAsset>({ hostname: '', ip_address: '', asset_type: 'server', ports: '' });

  const nameRef = useRef<HTMLInputElement>(null);
  const apiKeyRef = useRef<HTMLInputElement>(null);

  const [state, setState] = useState<SetupState>({
    authMethod: 'register',
    name: '',
    email: '',
    password: '',
    apiKey: '',
    loginMode: false,
    aiProvider: 'openrouter',
    aiProviderKey: '',
    ollamaUrl: 'http://localhost:11434',
    assetMode: 'auto',
    scanTarget: '',
    scanConsent: false,
    discoveredAssets: [],
    manualAssets: [],
    webhookEnabled: false,
    webhookUrl: '',
    telegramEnabled: false,
    telegramBotToken: '',
    telegramChatId: '',
  });

  useEffect(() => {
    setTimeout(() => setMounted(true), 50);
  }, []);

  useEffect(() => {
    if (mounted && step === 1) {
      setTimeout(() => {
        if (state.authMethod === 'register') nameRef.current?.focus();
        else apiKeyRef.current?.focus();
      }, 400);
    }
  }, [mounted, step, state.authMethod]);

  // Simulate scan progress
  useEffect(() => {
    if (!scanning) {
      setScanProgress(0);
      return;
    }
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) return prev;
        return prev + Math.random() * 8;
      });
    }, 500);
    return () => clearInterval(interval);
  }, [scanning]);

  const update = useCallback((patch: Partial<SetupState>) => {
    setState(prev => ({ ...prev, ...patch }));
    setError('');
  }, []);

  const markCompleted = (stepId: number) => {
    setCompletedSteps(prev => ({ ...prev, [stepId]: true }));
  };

  const animateStep = (next: number) => {
    setStepTransition(true);
    setTimeout(() => {
      setStep(next);
      setStepTransition(false);
    }, 200);
  };

  /* ── Step Handlers ── */

  const handleStep1 = async () => {
    if (state.authMethod === 'register' && !state.loginMode) {
      if (!state.name.trim()) return setError('Name is required');
      if (!state.email.trim()) return setError('Email is required');
      if (!state.password || state.password.length < 6) return setError('Password must be at least 6 characters');
    } else if (state.authMethod === 'register' && state.loginMode) {
      if (!state.email.trim()) return setError('Email is required');
      if (!state.password) return setError('Password is required');
    } else {
      if (!state.apiKey.trim()) return setError('API key is required');
    }

    setLoading(true);
    setError('');
    try {
      if (state.authMethod === 'register') {
        if (state.loginMode) {
          const result = await api.auth.loginCredentials(state.email.trim(), state.password);
          if (result.token) setJwtToken(result.token);
        } else {
          const result = await api.auth.register(state.name.trim(), state.email.trim(), state.password);
          if (result.token) setJwtToken(result.token);
        }
      } else {
        setApiKey(state.apiKey.trim());
        try {
          await api.auth.login(state.apiKey.trim());
        } catch {
          // API key stored locally, continue even if validation fails
        }
      }
      markCompleted(1);
      animateStep(2);
    } catch (err: unknown) {
      // Check if 401 means admin already exists
      const isApiError = err && typeof err === 'object' && 'status' in err;
      if (isApiError && (err as { status: number }).status === 401 && !state.loginMode) {
        setError('An admin account already exists. Please login instead.');
        update({ loginMode: true });
      } else if (isApiError && (err as { status: number }).status === 401 && state.loginMode) {
        setError('Invalid credentials. Please try again.');
      } else {
        // Backend unavailable — allow continuing for setup flow
        if (state.authMethod === 'apikey') {
          setApiKey(state.apiKey.trim());
        }
        markCompleted(1);
        animateStep(2);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStep2 = async () => {
    if (state.aiProvider !== 'skip') {
      if (state.aiProvider === 'ollama') {
        if (!state.ollamaUrl.trim()) return setError('Ollama URL is required');
      } else if (!state.aiProviderKey.trim()) {
        return setError('API key is required');
      }
    }

    setLoading(true);
    setError('');
    try {
      if (state.aiProvider !== 'skip') {
        try {
          await api.ai.setActive(state.aiProvider);
          const config: Record<string, string> = {};
          if (state.aiProvider === 'ollama') {
            config.base_url = state.ollamaUrl.trim();
          } else {
            config.api_key = state.aiProviderKey.trim();
          }
          await api.ai.configure(state.aiProvider, config);
        } catch {
          // Silently continue if AI config fails (401 or network error)
        }
      }
    } catch {
      // Continue even if AI config fails
    }
    setLoading(false);
    markCompleted(2);
    animateStep(3);
  };

  const handleSkipStep = (currentStep: number) => {
    markCompleted(currentStep);
    animateStep(currentStep + 1);
  };

  const handleDiscover = async () => {
    if (!state.scanTarget.trim()) return setError('Enter an IP address or range to scan');
    if (!state.scanConsent) return setError('Please confirm you understand the scan operation');
    setScanning(true);
    setScanProgress(0);
    setError('');
    try {
      const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

      // Launch scan — no auth required for setup endpoints
      const launchRes = await fetch(`${BASE}/setup/discover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: state.scanTarget.trim() }),
      });
      const launch = await launchRes.json();
      const scanId = launch.scan_id as string;
      if (!scanId) throw new Error('No scan_id returned');

      // Poll for results (max 60 seconds)
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const res = await fetch(`${BASE}/setup/discover/${scanId}`, {
          headers: { 'Content-Type': 'application/json' },
        });
        const data = await res.json();
        if (data.status === 'completed' && data.services) {
          if (data.services.length === 0) {
            setError('No services found. The host may be blocking scans. Try adding assets manually.');
            return;
          }
          const assets: DiscoveredAsset[] = data.services.map(
            (s: { port: number; service: string; hostname?: string; version?: string; risk_estimate?: number }, idx: number) => ({
              id: `disc-${idx}`,
              hostname: s.hostname || `${s.service}-${state.scanTarget}`,
              ip_address: data.target || state.scanTarget.trim(),
              asset_type: s.service?.includes('http') ? 'web_application' : s.service?.includes('ssh') ? 'server' : 'server',
              ports: [s.port],
              status: 'active',
              selected: true,
              service_name: s.service,
              version: s.version,
              risk_score: s.risk_estimate,
            })
          );
          setScanProgress(100);
          update({ discoveredAssets: assets });
          return;
        }
        if (data.status === 'failed') {
          setError(`Scan failed: ${data.error || 'Unknown error'}. Try adding assets manually.`);
          return;
        }
      }
      setError('Scan timed out. Try adding assets manually.');
    } catch {
      setError('Scan failed or backend unavailable. You can add assets manually.');
    } finally {
      setScanning(false);
    }
  };

  const handleAddManual = () => {
    if (!manualForm.hostname.trim()) return setError('Hostname is required');
    if (!manualForm.ip_address.trim()) return setError('IP Address is required');
    const ports = manualForm.ports
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p) && p > 0 && p <= 65535);
    const newAsset: DiscoveredAsset = {
      id: `manual-${Date.now()}`,
      hostname: manualForm.hostname.trim(),
      ip_address: manualForm.ip_address.trim(),
      asset_type: manualForm.asset_type,
      ports,
      status: 'active',
      selected: true,
    };
    update({ discoveredAssets: [...state.discoveredAssets, newAsset] });
    setManualForm({ hostname: '', ip_address: '', asset_type: 'server', ports: '' });
    setError('');
  };

  const handleRemoveAsset = (id: string) => {
    update({ discoveredAssets: state.discoveredAssets.filter(a => a.id !== id) });
  };

  const toggleAssetSelection = (id: string) => {
    update({
      discoveredAssets: state.discoveredAssets.map(a =>
        a.id === id ? { ...a, selected: !a.selected } : a
      ),
    });
  };

  const handleRegisterAssets = async () => {
    const selectedAssets = state.discoveredAssets.filter(a => a.selected);
    if (selectedAssets.length === 0) return setError('Select at least one asset to register');
    setLoading(true);
    try {
      const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
      await fetch(`${BASE}/setup/register-assets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          assets: selectedAssets.map(a => ({
            hostname: a.hostname,
            ip_address: a.ip_address,
            asset_type: a.asset_type,
          })),
        }),
      });
    } catch {
      // Continue even if registration fails
    }
    setLoading(false);
    markCompleted(3);
    animateStep(4);
  };

  const handleStep3 = async () => {
    const selectedAssets = state.discoveredAssets.filter(a => a.selected);
    if (selectedAssets.length > 0) {
      await handleRegisterAssets();
    } else {
      markCompleted(3);
      animateStep(4);
    }
  };

  const handleStep4 = async () => {
    setLoading(true);
    setError('');
    try {
      const data: Record<string, unknown> = {};
      if (state.webhookEnabled && state.webhookUrl.trim()) {
        data.webhook_url = state.webhookUrl.trim();
      }
      if (state.telegramEnabled) {
        data.telegram_enabled = true;
        data.telegram_bot_token = state.telegramBotToken.trim();
        data.telegram_chat_id = state.telegramChatId.trim();
      }
      if (Object.keys(data).length > 0) {
        try {
          await api.settings.updateNotifications(data);
        } catch {
          // Continue even if notification config fails
        }
      }
    } catch {
      // Continue
    }
    setLoading(false);
    markCompleted(4);
    animateStep(5);
  };

  const handleFinish = () => {
    router.push('/dashboard');
  };

  const handleKeyDown = (e: React.KeyboardEvent, handler: () => void) => {
    if (e.key === 'Enter') handler();
  };

  /* ── Summary for Step 5 ── */

  const summaryItems = () => {
    const items: { label: string; value: string; done: boolean }[] = [];
    items.push({
      label: 'Account',
      value: state.authMethod === 'register' ? state.email || 'Configured' : 'API Key',
      done: !!completedSteps[1],
    });
    items.push({
      label: 'AI Provider',
      value: state.aiProvider === 'skip' ? 'Not configured' : state.aiProvider.charAt(0).toUpperCase() + state.aiProvider.slice(1),
      done: state.aiProvider !== 'skip' && !!completedSteps[2],
    });
    const selectedCount = state.discoveredAssets.filter(a => a.selected).length;
    items.push({
      label: 'Assets',
      value: selectedCount > 0 ? `${selectedCount} asset${selectedCount > 1 ? 's' : ''} registered` : 'None added',
      done: selectedCount > 0,
    });
    items.push({
      label: 'Alerts',
      value: state.webhookEnabled || state.telegramEnabled
        ? [state.webhookEnabled && 'Webhook', state.telegramEnabled && 'Telegram'].filter(Boolean).join(', ')
        : 'Not configured',
      done: state.webhookEnabled || state.telegramEnabled,
    });
    return items;
  };

  /* ──────────────────────────────────────────────
     Render
     ────────────────────────────────────────────── */

  return (
    <div className="min-h-screen bg-[#09090B] flex flex-col items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background glows */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(34,211,238,0.04) 0%, transparent 70%)' }}
      />
      <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(249,115,22,0.03) 0%, transparent 70%)' }}
      />

      <div className={`relative w-full max-w-2xl z-10 transition-all duration-700 ease-out ${
        mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
      }`}>
        {/* Step Indicator */}
        <div className="flex items-center justify-center gap-2 mb-10">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex items-center">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-300 ${
                step === s.id
                  ? 'bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/20'
                  : completedSteps[s.id]
                  ? 'bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/20'
                  : 'text-zinc-600 border border-white/[0.06]'
              }`}>
                {completedSteps[s.id] && step !== s.id ? (
                  <Check className="w-3 h-3" />
                ) : (
                  <span className="font-mono text-[10px]">{s.id}</span>
                )}
                <span className="hidden sm:inline">{s.label}</span>
              </div>
              {i < STEPS.length - 1 && (
                <div className={`w-6 h-px mx-1 transition-colors duration-300 ${
                  completedSteps[s.id] ? 'bg-[#22C55E]/30' : 'bg-white/[0.06]'
                }`} />
              )}
            </div>
          ))}
        </div>

        {/* Content Card */}
        <div className={`bg-[#18181B] border border-white/[0.06] rounded-2xl p-8 transition-all duration-200 ${
          stepTransition ? 'opacity-0 translate-y-2' : 'opacity-100 translate-y-0'
        }`}>

          {/* --- STEP 1: Account --- */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 mb-4">
                  <ShieldCheck className="w-6 h-6 text-[#22D3EE]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Welcome to AEGIS</h2>
                <p className="text-zinc-500 text-sm mt-2">
                  {state.loginMode ? 'Login to your existing account' : 'Set up your account to get started'}
                </p>
              </div>

              {/* Auth method toggle */}
              <div className="flex rounded-xl bg-[#09090B] border border-white/[0.06] p-1">
                <button
                  onClick={() => update({ authMethod: 'register', loginMode: false })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.authMethod === 'register'
                      ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <User className="w-3.5 h-3.5" />
                  {state.loginMode ? 'Login' : 'Create Account'}
                </button>
                <button
                  onClick={() => update({ authMethod: 'apikey', loginMode: false })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.authMethod === 'apikey'
                      ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  API Key
                </button>
              </div>

              {state.authMethod === 'register' ? (
                <div className="space-y-4">
                  {!state.loginMode && (
                    <InputField
                      ref={nameRef}
                      label="Name"
                      icon={User}
                      value={state.name}
                      onChange={v => update({ name: v })}
                      onKeyDown={e => handleKeyDown(e, handleStep1)}
                      placeholder="Your name"
                    />
                  )}
                  <InputField
                    label="Email"
                    icon={Mail}
                    type="email"
                    value={state.email}
                    onChange={v => update({ email: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder="admin@organization.com"
                    autoComplete="email"
                  />
                  <InputField
                    label="Password"
                    icon={Lock}
                    type="password"
                    value={state.password}
                    onChange={v => update({ password: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder={state.loginMode ? 'Your password' : 'Min 6 characters'}
                    autoComplete={state.loginMode ? 'current-password' : 'new-password'}
                  />
                  {state.loginMode && (
                    <button
                      onClick={() => update({ loginMode: false })}
                      className="text-xs text-zinc-500 hover:text-[#22D3EE] transition-colors"
                    >
                      Need to create an account instead?
                    </button>
                  )}
                </div>
              ) : (
                <div className="space-y-4">
                  <InputField
                    ref={apiKeyRef}
                    label="API Key"
                    icon={KeyRound}
                    type="password"
                    value={state.apiKey}
                    onChange={v => update({ apiKey: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder="Enter your API key"
                  />
                  <p className="text-xs text-zinc-600">
                    The key will be stored locally and used for all API requests.
                  </p>
                </div>
              )}

              {error && <ErrorMessage message={error} />}

              <StepButton label={state.loginMode ? 'Login' : 'Continue'} loading={loading} onClick={handleStep1} />
            </div>
          )}

          {/* --- STEP 2: AI Provider --- */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 mb-4">
                  <Cpu className="w-6 h-6 text-[#22D3EE]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Connect AI Provider</h2>
                <p className="text-zinc-500 text-sm mt-2">AEGIS uses AI for threat analysis and autonomous response</p>
              </div>

              <div className="space-y-2">
                {AI_PROVIDERS.map(p => {
                  const Icon = p.icon;
                  return (
                    <button
                      key={p.id}
                      onClick={() => update({ aiProvider: p.id })}
                      className={`w-full flex items-center gap-4 p-4 rounded-xl border transition-all duration-200 text-left ${
                        state.aiProvider === p.id
                          ? 'border-[#22D3EE]/30 bg-[#22D3EE]/5'
                          : 'border-white/[0.06] hover:border-white/[0.1] hover:bg-white/[0.02]'
                      }`}
                    >
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                        state.aiProvider === p.id ? 'bg-[#22D3EE]/10' : 'bg-white/[0.04]'
                      }`}>
                        <Icon className={`w-4 h-4 ${state.aiProvider === p.id ? 'text-[#22D3EE]' : 'text-zinc-500'}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className={`text-sm font-medium ${state.aiProvider === p.id ? 'text-white' : 'text-zinc-300'}`}>
                          {p.label}
                        </div>
                        <div className="text-xs text-zinc-500">{p.description}</div>
                      </div>
                      {state.aiProvider === p.id && (
                        <div className="w-5 h-5 rounded-full bg-[#22D3EE] flex items-center justify-center">
                          <Check className="w-3 h-3 text-[#09090B]" />
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {state.aiProvider !== 'skip' && state.aiProvider !== 'ollama' && (
                <InputField
                  label={`${state.aiProvider.charAt(0).toUpperCase() + state.aiProvider.slice(1)} API Key`}
                  icon={KeyRound}
                  type="password"
                  value={state.aiProviderKey}
                  onChange={v => update({ aiProviderKey: v })}
                  onKeyDown={e => handleKeyDown(e, handleStep2)}
                  placeholder="sk-..."
                />
              )}

              {state.aiProvider === 'ollama' && (
                <InputField
                  label="Ollama URL"
                  icon={Globe}
                  value={state.ollamaUrl}
                  onChange={v => update({ ollamaUrl: v })}
                  onKeyDown={e => handleKeyDown(e, handleStep2)}
                  placeholder="http://localhost:11434"
                />
              )}

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(1)} />
                <StepButton label="Continue" loading={loading} onClick={handleStep2} />
                <SkipButton onClick={() => handleSkipStep(2)} />
              </div>
            </div>
          )}

          {/* --- STEP 3: Discover Assets --- */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 mb-4">
                  <Wifi className="w-6 h-6 text-[#22D3EE]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Discover Your Assets</h2>
                <p className="text-zinc-500 text-sm mt-2">Scan your network or add assets manually</p>
              </div>

              {/* Mode Toggle */}
              <div className="flex rounded-xl bg-[#09090B] border border-white/[0.06] p-1">
                <button
                  onClick={() => update({ assetMode: 'auto' })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.assetMode === 'auto'
                      ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <Search className="w-3.5 h-3.5" />
                  Auto-Scan
                </button>
                <button
                  onClick={() => update({ assetMode: 'manual' })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.assetMode === 'manual'
                      ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <Plus className="w-3.5 h-3.5" />
                  Manual
                </button>
              </div>

              {/* AUTO-SCAN MODE */}
              {state.assetMode === 'auto' && (
                <div className="space-y-4">
                  {/* Warning Card */}
                  <div className="rounded-xl border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-4">
                    <div className="flex gap-3">
                      <AlertTriangle className="w-5 h-5 text-[#F59E0B] flex-shrink-0 mt-0.5" />
                      <div className="space-y-2">
                        <p className="text-sm text-zinc-300">
                          AEGIS will scan your network to discover services.
                          This runs nmap from the server to detect open ports and services.
                        </p>
                        <p className="text-xs text-zinc-500">
                          No changes will be made to your systems -- this is read-only reconnaissance.
                        </p>
                        <label className="flex items-center gap-2 mt-3 cursor-pointer select-none">
                          <button
                            onClick={() => update({ scanConsent: !state.scanConsent })}
                            className={`w-4 h-4 rounded border flex items-center justify-center transition-all flex-shrink-0 ${
                              state.scanConsent
                                ? 'bg-[#22D3EE] border-[#22D3EE]'
                                : 'border-white/20 hover:border-white/40'
                            }`}
                          >
                            {state.scanConsent && <Check className="w-2.5 h-2.5 text-[#09090B]" />}
                          </button>
                          <span className="text-xs text-zinc-400">I understand and want to proceed</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  {/* Scan controls — only visible after consent */}
                  {state.scanConsent && (
                    <div className="space-y-4">
                      <div className="flex gap-2">
                        <div className="flex-1">
                          <InputField
                            label="Target IP / Range"
                            icon={Search}
                            value={state.scanTarget}
                            onChange={v => update({ scanTarget: v })}
                            onKeyDown={e => handleKeyDown(e, handleDiscover)}
                            placeholder="e.g., 192.168.1.0/24 or 10.0.0.1"
                          />
                        </div>
                        <button
                          onClick={handleDiscover}
                          disabled={scanning || !state.scanTarget.trim()}
                          className="self-end mb-[1px] px-5 py-3 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 text-[#22D3EE] text-sm font-medium hover:bg-[#22D3EE]/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
                        >
                          {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                          {scanning ? 'Scanning' : 'Scan'}
                        </button>
                      </div>

                      {/* Scanning progress */}
                      {scanning && (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <Loader2 className="w-4 h-4 animate-spin text-[#22D3EE]" />
                            <span className="text-sm text-zinc-400">Scanning... this may take up to 60 seconds</span>
                          </div>
                          <div className="w-full h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                            <div
                              className="h-full bg-[#22D3EE] rounded-full transition-all duration-500 ease-out"
                              style={{ width: `${Math.min(scanProgress, 100)}%` }}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* MANUAL MODE */}
              {state.assetMode === 'manual' && (
                <div className="space-y-4">
                  <div className="bg-[#09090B] border border-white/[0.06] rounded-xl p-4 space-y-4">
                    <InputField
                      label="Hostname"
                      icon={Monitor}
                      value={manualForm.hostname}
                      onChange={v => setManualForm(prev => ({ ...prev, hostname: v }))}
                      placeholder="e.g., web-server-01"
                    />
                    <InputField
                      label="IP Address"
                      icon={Globe}
                      value={manualForm.ip_address}
                      onChange={v => setManualForm(prev => ({ ...prev, ip_address: v }))}
                      placeholder="e.g., 192.168.1.100"
                    />
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-2">Type</label>
                      <div className="relative">
                        <Server className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                        <select
                          value={manualForm.asset_type}
                          onChange={e => setManualForm(prev => ({ ...prev, asset_type: e.target.value }))}
                          className="w-full bg-[#18181B] border border-white/[0.06] text-white rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[#22D3EE]/40 focus:ring-1 focus:ring-[#22D3EE]/20 transition-all duration-200 appearance-none"
                        >
                          {ASSET_TYPES.map(t => (
                            <option key={t.value} value={t.value}>{t.label}</option>
                          ))}
                        </select>
                      </div>
                    </div>
                    <InputField
                      label="Port(s)"
                      icon={Wifi}
                      value={manualForm.ports}
                      onChange={v => setManualForm(prev => ({ ...prev, ports: v }))}
                      placeholder="e.g., 80, 443, 8080"
                    />
                    <button
                      onClick={handleAddManual}
                      className="w-full px-4 py-2.5 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 text-[#22D3EE] text-sm font-medium hover:bg-[#22D3EE]/20 transition-all duration-200 flex items-center justify-center gap-2"
                    >
                      <Plus className="w-4 h-4" />
                      Add Asset
                    </button>
                  </div>
                </div>
              )}

              {/* Discovered / Added assets list (shared between both modes) */}
              {state.discoveredAssets.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-zinc-400">
                      {state.discoveredAssets.length} asset{state.discoveredAssets.length !== 1 ? 's' : ''} found
                      {' '}&middot;{' '}
                      {state.discoveredAssets.filter(a => a.selected).length} selected
                    </span>
                  </div>
                  <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1">
                    {state.discoveredAssets.map(asset => {
                      const AssetIcon = getAssetIcon(asset.asset_type);
                      return (
                        <div
                          key={asset.id}
                          className={`flex items-center gap-3 p-3 rounded-xl border transition-all duration-200 ${
                            asset.selected
                              ? 'border-[#22D3EE]/20 bg-[#22D3EE]/5'
                              : 'border-white/[0.06] bg-white/[0.02] opacity-60'
                          }`}
                        >
                          <button
                            onClick={() => toggleAssetSelection(asset.id)}
                            className={`w-5 h-5 rounded-md border flex items-center justify-center transition-all flex-shrink-0 ${
                              asset.selected
                                ? 'bg-[#22D3EE] border-[#22D3EE]'
                                : 'border-white/20 hover:border-white/40'
                            }`}
                          >
                            {asset.selected && <Check className="w-3 h-3 text-[#09090B]" />}
                          </button>
                          <AssetIcon className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm text-white truncate">
                              {asset.service_name ? (
                                <span>
                                  <span className="text-zinc-400">:{asset.ports[0]}</span>{' '}
                                  {asset.service_name}
                                  {asset.version && <span className="text-zinc-500 text-xs ml-1">{asset.version}</span>}
                                </span>
                              ) : (
                                asset.hostname || asset.ip_address
                              )}
                            </div>
                            <div className="text-xs text-zinc-500">
                              {asset.ip_address}{asset.ports.length > 0 && !asset.service_name && ` - Ports: ${asset.ports.join(', ')}`}
                            </div>
                          </div>
                          {asset.risk_score !== undefined && (
                            <span className={`text-[10px] font-bold ${getRiskColor(asset.risk_score)} bg-white/[0.04] px-2 py-0.5 rounded`}>
                              {getRiskLabel(asset.risk_score)} ({asset.risk_score.toFixed(1)})
                            </span>
                          )}
                          <span className="text-[10px] font-medium text-zinc-500 uppercase bg-white/[0.04] px-2 py-0.5 rounded hidden sm:inline">
                            {asset.asset_type.replace('_', ' ')}
                          </span>
                          <button
                            onClick={() => handleRemoveAsset(asset.id)}
                            className="text-zinc-600 hover:text-[#EF4444] transition-colors flex-shrink-0"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      );
                    })}
                  </div>

                  {/* Register Selected button */}
                  <button
                    onClick={handleRegisterAssets}
                    disabled={loading || state.discoveredAssets.filter(a => a.selected).length === 0}
                    className="w-full mt-2 px-4 py-2.5 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 text-[#22D3EE] text-sm font-medium hover:bg-[#22D3EE]/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                    Register Selected Assets ({state.discoveredAssets.filter(a => a.selected).length})
                  </button>
                </div>
              )}

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(2)} />
                <StepButton
                  label={state.discoveredAssets.filter(a => a.selected).length > 0 ? 'Register & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep3}
                />
                <SkipButton onClick={() => handleSkipStep(3)} />
              </div>
            </div>
          )}

          {/* --- STEP 4: Alerts --- */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 mb-4">
                  <Bell className="w-6 h-6 text-[#22D3EE]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Configure Alerts</h2>
                <p className="text-zinc-500 text-sm mt-2">Get notified when AEGIS detects threats</p>
              </div>

              {/* Webhook */}
              <div className={`p-4 rounded-xl border transition-all duration-200 ${
                state.webhookEnabled ? 'border-[#22D3EE]/20 bg-[#22D3EE]/5' : 'border-white/[0.06]'
              }`}>
                <button
                  onClick={() => update({ webhookEnabled: !state.webhookEnabled })}
                  className="w-full flex items-center gap-3 text-left"
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    state.webhookEnabled ? 'bg-[#22D3EE]/10' : 'bg-white/[0.04]'
                  }`}>
                    <Webhook className={`w-4 h-4 ${state.webhookEnabled ? 'text-[#22D3EE]' : 'text-zinc-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Webhook</div>
                    <div className="text-xs text-zinc-500">Send alerts to a webhook URL</div>
                  </div>
                  <ToggleSwitch enabled={state.webhookEnabled} />
                </button>
                {state.webhookEnabled && (
                  <div className="mt-4">
                    <InputField
                      label="Webhook URL"
                      icon={Globe}
                      value={state.webhookUrl}
                      onChange={v => update({ webhookUrl: v })}
                      placeholder="https://hooks.slack.com/..."
                    />
                  </div>
                )}
              </div>

              {/* Telegram */}
              <div className={`p-4 rounded-xl border transition-all duration-200 ${
                state.telegramEnabled ? 'border-[#22D3EE]/20 bg-[#22D3EE]/5' : 'border-white/[0.06]'
              }`}>
                <button
                  onClick={() => update({ telegramEnabled: !state.telegramEnabled })}
                  className="w-full flex items-center gap-3 text-left"
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    state.telegramEnabled ? 'bg-[#22D3EE]/10' : 'bg-white/[0.04]'
                  }`}>
                    <Send className={`w-4 h-4 ${state.telegramEnabled ? 'text-[#22D3EE]' : 'text-zinc-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Telegram</div>
                    <div className="text-xs text-zinc-500">Send alerts via Telegram bot</div>
                  </div>
                  <ToggleSwitch enabled={state.telegramEnabled} />
                </button>
                {state.telegramEnabled && (
                  <div className="mt-4 space-y-3">
                    <InputField
                      label="Bot Token"
                      icon={KeyRound}
                      value={state.telegramBotToken}
                      onChange={v => update({ telegramBotToken: v })}
                      placeholder="123456:ABC-DEF..."
                    />
                    <InputField
                      label="Chat ID"
                      icon={Mail}
                      value={state.telegramChatId}
                      onChange={v => update({ telegramChatId: v })}
                      placeholder="-1001234567890"
                    />
                  </div>
                )}
              </div>

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(3)} />
                <StepButton
                  label={state.webhookEnabled || state.telegramEnabled ? 'Save & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep4}
                />
                <SkipButton onClick={() => handleSkipStep(4)} />
              </div>
            </div>
          )}

          {/* --- STEP 5: Ready --- */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#22C55E]/10 border border-[#22C55E]/20 mb-4">
                  <Check className="w-6 h-6 text-[#22C55E]" />
                </div>
                <h2 className="text-2xl font-bold text-white">You&apos;re All Set</h2>
                <p className="text-zinc-500 text-sm mt-2">AEGIS is ready to defend your infrastructure</p>
              </div>

              <div className="space-y-2">
                {summaryItems().map(item => (
                  <div key={item.label} className="flex items-center gap-3 p-3 rounded-xl border border-white/[0.06]">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center ${
                      item.done ? 'bg-[#22C55E]/10' : 'bg-white/[0.04]'
                    }`}>
                      {item.done ? (
                        <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      ) : (
                        <X className="w-3.5 h-3.5 text-zinc-500" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="text-sm font-medium text-white">{item.label}</div>
                      <div className="text-xs text-zinc-500">{item.value}</div>
                    </div>
                  </div>
                ))}
              </div>

              <button
                onClick={handleFinish}
                className="w-full bg-[#22D3EE] hover:bg-[#06B6D4] text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[#22D3EE]/10 active:scale-[0.98] flex items-center justify-center gap-2"
              >
                Go to Dashboard
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-zinc-700 mt-8">
          AEGIS Defense Platform &middot; v1.0.0
        </p>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────
   Sub-components
   ────────────────────────────────────────────── */

interface InputFieldProps {
  label: string;
  icon: typeof Lock;
  value: string;
  onChange: (v: string) => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  placeholder?: string;
  type?: string;
  autoComplete?: string;
}

const InputField = forwardRef<HTMLInputElement, InputFieldProps>(function InputField(
  { label, icon: Icon, value, onChange, onKeyDown, placeholder, type = 'text', autoComplete },
  ref
) {
  return (
    <div>
      <label className="block text-xs font-medium text-zinc-400 mb-2">{label}</label>
      <div className="relative">
        <Icon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
        <input
          ref={ref}
          type={type}
          value={value}
          onChange={e => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          autoComplete={autoComplete}
          spellCheck={false}
          className="w-full bg-[#09090B] border border-white/[0.06] text-white placeholder-zinc-600 rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[#22D3EE]/40 focus:ring-1 focus:ring-[#22D3EE]/20 transition-all duration-200"
        />
      </div>
    </div>
  );
});

function StepButton({ label, loading, onClick }: { label: string; loading: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="flex-1 bg-[#22D3EE] hover:bg-[#06B6D4] disabled:opacity-50 disabled:cursor-not-allowed text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[#22D3EE]/10 active:scale-[0.98] flex items-center justify-center gap-2"
    >
      {loading ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          Processing...
        </>
      ) : (
        <>
          {label}
          <ChevronRight className="w-4 h-4" />
        </>
      )}
    </button>
  );
}

function BackButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-5 py-3 rounded-xl border border-white/[0.06] text-zinc-400 hover:text-white hover:border-white/[0.1] transition-all duration-200 flex items-center gap-1"
    >
      <ChevronLeft className="w-4 h-4" />
      Back
    </button>
  );
}

function SkipButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-4 py-3 rounded-xl text-zinc-600 hover:text-zinc-400 text-sm font-medium transition-all duration-200"
    >
      Skip
    </button>
  );
}

function ErrorMessage({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 text-[#EF4444] text-xs font-medium bg-[#EF4444]/5 border border-[#EF4444]/10 rounded-xl p-3">
      <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  );
}

function ToggleSwitch({ enabled }: { enabled: boolean }) {
  return (
    <div className={`w-10 h-5 rounded-full transition-colors duration-200 relative ${
      enabled ? 'bg-[#22D3EE]' : 'bg-white/10'
    }`}>
      <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${
        enabled ? 'translate-x-5' : 'translate-x-0.5'
      }`} />
    </div>
  );
}
