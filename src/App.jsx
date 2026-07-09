import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle,
  Search,
  Terminal,
  Plus,
  Globe,
  Lock,
  Unlock,
  Settings as SettingsIcon,
  Activity,
  FileText,
  RefreshCw,
  GitPullRequest,
  Eye,
  EyeOff,
  ArrowRight,
  ChevronRight,
  Download,
  ExternalLink,
  FileCode,
  Check,
  Send,
  MessageSquare,
  Server,
  Cloud,
  ChevronDown,
  User,
  Sliders,
  Database,
  Menu,
  X
} from 'lucide-react';
import { createClient } from '@supabase/supabase-js';
import { usePaystackPayment } from 'react-paystack';

// Custom SVG Github icon for branding
function GithubIcon({ size = 20, color = "currentColor", ...props }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      stroke={color}
      strokeWidth="2"
      fill="none"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
    </svg>
  );
}

// Backend API URL (Automatically routes to Vercel Serverless Functions in production)
const BACKEND_URL = import.meta.env.PROD ? 'https://geolzen.onrender.com' : 'http://localhost:5000';

// Mock Initial Targets
const INITIAL_TARGETS = [];

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(localStorage.getItem('geolzen_auth') === 'true');
  const [showAuthGate, setShowAuthGate] = useState(false);
  const [authMode, setAuthMode] = useState('login'); // login or signup

  // Privacy Policy modal states
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [privacyAgreed, setPrivacyAgreed] = useState(false);

  // Mobile Hamburger menu toggle state
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Supabase Credentials and Client states
  const [supabaseUrl, setSupabaseUrl] = useState('');
  const [supabaseAnonKey, setSupabaseAnonKey] = useState('');
  const [supabaseStatus, setSupabaseStatus] = useState('disconnected');
  const [supabaseClient, setSupabaseClient] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [authMessage, setAuthMessage] = useState(null);
  const [isDbsyncing, setIsDbsyncing] = useState(false);

  // Personalization settings state
  const [userProfile, setUserProfile] = useState(() => {
    const saved = localStorage.getItem('geolzen_profile');
    if (saved) return JSON.parse(saved);
    return {
      fullName: '',
      email: '',
      orgName: ''
    };
  });

  // Settings tab sub-view
  const [settingsView, setSettingsView] = useState('profile'); // profile, alerts, supabase

  // Form edit states
  const [editFullName, setEditFullName] = useState('');
  const [editOrgName, setEditOrgName] = useState('');
  const [slackWebhookUrl, setSlackWebhookUrl] = useState('');
  const [enableEmailAlerts, setEnableEmailAlerts] = useState(true);
  const [enableSlackAlerts, setEnableSlackAlerts] = useState(false);
  const [scanIntensity, setScanIntensity] = useState('safe'); // safe or aggressive

  // Auth inputs
  const [authFullNameInput, setAuthFullNameInput] = useState('');
  const [authOrgInput, setAuthOrgInput] = useState('');
  const [authEmailInput, setAuthEmailInput] = useState('');
  const [authPasswordInput, setAuthPasswordInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [authOtpInput, setAuthOtpInput] = useState('');
  const [authNewPasswordInput, setAuthNewPasswordInput] = useState('');

  // Platform state
  const [targets, setTargets] = useState(INITIAL_TARGETS);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedTargetId, setSelectedTargetId] = useState('target-1');
  const [selectedVulnId, setSelectedVulnId] = useState('vuln-1');
  
  // Landing Page TRY scanner widget states
  const [tryUrl, setTryUrl] = useState('');
  const [tryLoading, setTryLoading] = useState(false);
  const [tryResult, setTryResult] = useState(null);

  // Target add states
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetType, setNewTargetType] = useState('domain');
  const [showAddModal, setShowAddModal] = useState(false);
  
  // Verification states
  const [activeVerifyTarget, setActiveVerifyTarget] = useState(null);
  const [verificationMethod, setVerificationMethod] = useState('dns');
  const [isVerifying, setIsVerifying] = useState(false);
  const [realDnsVerifyResponse, setRealDnsVerifyResponse] = useState(null);
  const [showHowToModal, setShowHowToModal] = useState(false);
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);
  const [upgradeModalReason, setUpgradeModalReason] = useState(null);
  
  // Legal Agreement States
  const [showLegalModal, setShowLegalModal] = useState(false);
  const [legalTarget, setLegalTarget] = useState(null);
  const [roeName, setRoeName] = useState('');
  const [roeCompany, setRoeCompany] = useState('');
  const [roeAccept, setRoeAccept] = useState(false);

  // Scan Console states
  const [consoleLogs, setConsoleLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanTypeSelection, setScanTypeSelection] = useState('active'); // active or passive
  const consoleEndRef = useRef(null);

  // Vulnerability Filters
  const [vulnFilter, setVulnFilter] = useState('all');

  // Support Chat Input states
  const [chatMessageInput, setChatMessageInput] = useState('');

  const selectedTarget = targets.find(t => t.id === selectedTargetId) || targets[0];
  const selectedVuln = selectedTarget?.vulnerabilities.find(v => v.id === selectedVulnId);

  const [orgData, setOrgData] = useState(null);
  const [paystackConfig, setPaystackConfig] = useState(null);

  // Use an exchange rate (e.g., $1 = 1500 NGN) to convert the USD price to Naira
  // This allows Nigerian Naira cards to work, while foreign banks will auto-convert it.
  const exchangeRate = 1500;
  const amountInNaira = paystackConfig?.amount ? (paystackConfig.amount * exchangeRate) : 0;

  const initializePayment = usePaystackPayment({
    reference: (new Date()).getTime().toString(),
    email: userProfile?.email || "user@geolzen.com",
    amount: amountInNaira * 100, // Paystack expects lowest currency unit (Kobo)
    publicKey: import.meta.env.VITE_PAYSTACK_PUBLIC_KEY || 'pk_test_dummy',
    currency: 'NGN'
  });

  useEffect(() => {
    if (paystackConfig && paystackConfig.amount > 0) {
      setTimeout(() => {
        initializePayment({
          onSuccess: async (ref) => {
            try {
              await fetch(`${BACKEND_URL}/api/payments/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reference: ref.reference, plan: paystackConfig.plan, organization_id: orgData?.id })
              });
              setPaystackConfig(null);
              window.location.reload();
            } catch (err) {
              console.error("Payment verification failed", err);
              setPaystackConfig(null);
            }
          },
          onClose: () => setPaystackConfig(null)
        });
      }, 100);
    }
  }, [paystackConfig]);

  const handleCheckout = (plan, amount) => {
    if (!isAuthenticated) {
      setAuthMode('signup');
      setShowAuthGate(true);
      return;
    }
    if (plan === 'free') return;
    setPaystackConfig({ plan, amount });
  };

  // On Mount: Check .env variables first, then local storage for Supabase credentials & load if present
  useEffect(() => {
    const envUrl = import.meta.env.VITE_SUPABASE_URL;
    const envKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
    
    if (envUrl && envKey) {
      setSupabaseUrl(envUrl);
      setSupabaseAnonKey(envKey);
      initSupabaseClient(envUrl, envKey);
    } else {
      const savedUrl = localStorage.getItem('geolzen_supabase_url');
      const savedKey = localStorage.getItem('geolzen_supabase_anon_key');
      if (savedUrl && savedKey) {
        setSupabaseUrl(savedUrl);
        setSupabaseAnonKey(savedKey);
        initSupabaseClient(savedUrl, savedKey);
      }
    }

    // Handle GitHub OAuth callback redirect
    const params = new URLSearchParams(window.location.search);
    const githubVerifiedId = params.get('github_verified');
    const githubError = params.get('github_error');

    if (githubVerifiedId) {
      // GitHub OAuth succeeded — update local target state
      setTargets(prev => prev.map(t => {
        if (t.id === githubVerifiedId) {
          return { ...t, verified: true, verificationMethod: 'oauth' };
        }
        return t;
      }));
      const verifiedTarget = targets.find(t => t.id === githubVerifiedId);
      if (verifiedTarget) {
        setLegalTarget({ ...verifiedTarget, verified: true, verificationMethod: 'oauth' });
        setShowLegalModal(true);
      }
      // Clean URL params
      window.history.replaceState({}, '', window.location.pathname);
    } else if (githubError) {
      setRealDnsVerifyResponse({
        success: false,
        message: `GitHub verification failed: ${decodeURIComponent(githubError)}`
      });
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  // Sync edits on profile state update
  useEffect(() => {
    setEditFullName(userProfile.fullName);
    setEditOrgName(userProfile.orgName);
    localStorage.setItem('geolzen_profile', JSON.stringify(userProfile));
  }, [userProfile]);

  // Autoscroll terminal
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs]);

  // Fetch targets & vulnerability details live from Supabase database if connected
  const syncDataFromSupabase = async (client) => {
    if (!client) return;
    setIsDbsyncing(true);
    try {
      const { data: dbTargets, error: targetError } = await client
        .from('targets')
        .select('*');
      
      if (targetError) throw targetError;

      const { data: dbOrgs } = await client.from('organizations').select('id, plan_tier').limit(1);
      if (dbOrgs && dbOrgs.length > 0) setOrgData(dbOrgs[0]);

      if (dbTargets && dbTargets.length > 0) {
        const { data: dbSigs } = await client
          .from('roe_signatures')
          .select('target_id, signed_at');

        const { data: dbVulns } = await client
          .from('vulnerabilities')
          .select('*');

        const { data: dbChats } = await client
          .from('chat_messages')
          .select('*')
          .order('created_at', { ascending: true });

        const mappedTargets = dbTargets.map(t => {
          const sig = dbSigs?.find(s => s.target_id === t.id);
          const targetVulns = dbVulns?.filter(v => v.target_id === t.id) || [];
          
          const counts = { critical: 0, high: 0, medium: 0, low: 0 };
          const mappedVulns = targetVulns.map(v => {
            if (!v.remediated) {
              counts[v.severity]++;
            }
            const chatHistory = dbChats?.filter(c => c.vulnerability_id === v.id).map(c => ({
              sender: c.sender,
              text: c.message
            })) || [];

            return {
              id: v.id,
              title: v.title,
              severity: v.severity,
              category: v.category,
              description: v.description,
              impact: v.impact,
              solution: v.solution,
              remediationType: v.remediation_type,
              remediated: v.remediated,
              fileName: v.file_name,
              originalCode: v.original_code,
              fixedCode: v.fixed_code,
              chatHistory: chatHistory.length > 0 ? chatHistory : [
                { sender: 'analyst', text: `Hi! Our scan found ${v.title}. Click "Generate Pull Request" above to fix, or ask me questions about mitigating this manually.` }
              ]
            };
          });

          return {
            id: t.id,
            name: t.name,
            type: t.type,
            verified: t.verified,
            verificationMethod: t.verification_method,
            verificationToken: t.verification_token,
            signedROE: !!sig,
            signedDate: sig ? sig.signed_at.replace('T', ' ').substring(0, 16) : null,
            scanStatus: mappedVulns.length > 0 ? 'completed' : 'idle',
            scanType: 'active',
            lastScanDate: sig ? sig.signed_at.replace('T', ' ').substring(0, 16) : null,
            vulnerabilitiesCount: counts,
            vulnerabilities: mappedVulns
          };
        });

        setTargets(mappedTargets);
        if (mappedTargets.length > 0) {
          setSelectedTargetId(mappedTargets[0].id);
          if (mappedTargets[0].vulnerabilities.length > 0) {
            setSelectedVulnId(mappedTargets[0].vulnerabilities[0].id);
          }
        }
      }
    } catch (err) {
      console.error("Error syncing Supabase data: ", err.message);
    } finally {
      setIsDbsyncing(false);
    }
  };

  const initSupabaseClient = (url, key) => {
    try {
      const client = createClient(url, key);
      setSupabaseClient(client);
      setSupabaseStatus('connected');
      syncDataFromSupabase(client);
      return client;
    } catch (e) {
      console.error(e);
      setSupabaseStatus('disconnected');
    }
    return null;
  };

  // Handler: Forgot Password via Supabase API
  const handleForgotPassword = async () => {
    if (!authEmailInput) {
      setAuthMessage({ type: 'error', text: 'Please enter your work email address first.' });
      return;
    }
    setAuthLoading(true);
    setAuthMessage(null);
    if (supabaseClient) {
      const { error } = await supabaseClient.auth.resetPasswordForEmail(authEmailInput);
      if (error) {
        setAuthMessage({ type: 'error', text: error.message });
      } else {
        setAuthMessage({ type: 'success', text: '6-digit OTP sent to your email! Please enter it below.' });
        setAuthMode('reset_otp');
      }
    } else {
      setAuthMessage({ type: 'error', text: 'Cannot send reset link in sandbox mode.' });
    }
    setAuthLoading(false);
  };

  // Handler: Sign In/Sign Up Submission via Supabase API
  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthMessage(null);

    if (supabaseClient) {
      try {
        if (authMode === 'reset_otp') {
          const { error } = await supabaseClient.auth.verifyOtp({
            email: authEmailInput,
            token: authOtpInput,
            type: 'recovery'
          });
          if (error) throw error;
          
          setAuthMessage({ type: 'success', text: 'OTP verified! Please create your new password.' });
          setAuthMode('new_password');
          setAuthLoading(false);
          return;

        } else if (authMode === 'new_password') {
          const { error } = await supabaseClient.auth.updateUser({
            password: authNewPasswordInput
          });
          if (error) throw error;
          
          setAuthMessage({ type: 'success', text: 'Password successfully updated! Logging you in...' });
          setTimeout(() => {
            setAuthMode('login');
            setAuthPasswordInput(authNewPasswordInput);
            setAuthMessage(null);
            document.querySelector('.auth-card form').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }, 2000);
          return;

        } else if (authMode === 'signup') {
          if (!privacyAgreed) {
            setAuthMessage({ type: 'error', text: 'You must agree to the Privacy Policy before creating an account.' });
            setAuthLoading(false);
            return;
          }

          const { data, error } = await supabaseClient.auth.signUp({
            email: authEmailInput,
            password: authPasswordInput,
            options: {
              data: {
                full_name: authFullNameInput || 'Security Operator',
                org_name: authOrgInput || 'Sandbox Corp'
              }
            }
          });

          if (error) throw error;
          
          if (data.session) {
            setAuthMessage({ type: 'success', text: 'Sign up successful! Logging you in...' });
            setTimeout(() => {
              setUserProfile({
                fullName: authFullNameInput || 'Security Operator',
                email: authEmailInput,
                orgName: authOrgInput || 'Sandbox Corp'
              });
              localStorage.setItem('geolzen_auth', 'true');
              setIsAuthenticated(true);
              setShowAuthGate(false);
            }, 2000);
          } else {
            setAuthMessage({ type: 'success', text: 'Sign up successful! Please check your email to confirm your account.' });
            setTimeout(() => {
              setAuthMode('login');
              setAuthMessage(null);
              setAuthLoading(false);
            }, 5000);
            return; // Exit early so we don't clear loading state immediately
          }

        } else {
          const { data, error } = await supabaseClient.auth.signInWithPassword({
            email: authEmailInput,
            password: authPasswordInput
          });

          if (error) throw error;

          const user = data.user;
          setUserProfile({
            fullName: user.user_metadata?.full_name || 'Security Operator',
            email: user.email,
            orgName: user.user_metadata?.org_name || 'Sandbox Corp'
          });
          localStorage.setItem('geolzen_auth', 'true');
          setIsAuthenticated(true);
          setShowAuthGate(false);
          syncDataFromSupabase(supabaseClient);
        }
      } catch (err) {
        setAuthMessage({ type: 'error', text: err.message });
      } finally {
        setAuthLoading(false);
      }
    } else {
      // Sandbox fallback mode
      setTimeout(() => {
        if (authMode === 'signup' && !privacyAgreed) {
          setAuthMessage({ type: 'error', text: 'You must agree to the Privacy Policy before creating an account.' });
          setAuthLoading(false);
          return;
        }

        setUserProfile({
          fullName: authFullNameInput || 'Jane Operator',
          email: authEmailInput || 'jane@sandbox.com',
          orgName: authOrgInput || 'Sandbox Corp'
        });
        localStorage.setItem('geolzen_auth', 'true');
        setIsAuthenticated(true);
        setShowAuthGate(false);
        setAuthLoading(false);
      }, 1000);
    }
  };

  const handleProfileUpdate = (e) => {
    e.preventDefault();
    setUserProfile({
      ...userProfile,
      fullName: editFullName,
      orgName: editOrgName
    });
    alert("Profile settings updated successfully!");
  };

  const handleSupabaseConnect = (e) => {
    e.preventDefault();
    if (!supabaseUrl || !supabaseAnonKey) return;
    setSupabaseStatus('connecting');

    setTimeout(() => {
      const client = initSupabaseClient(supabaseUrl, supabaseAnonKey);
      if (client) {
        localStorage.setItem('geolzen_supabase_url', supabaseUrl);
        localStorage.setItem('geolzen_supabase_anon_key', supabaseAnonKey);
        setSupabaseStatus('connected');
      } else {
        setSupabaseStatus('disconnected');
      }
    }, 1200);
  };

  const runLandingScanner = async (e) => {
    e.preventDefault();
    if (!tryUrl) return;
    setTryLoading(true);
    setTryResult(null);

    const cleanDomain = tryUrl.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();

    try {
      // Make a real HTTP request to fetch headers from the target
      const targetUrl = `https://${cleanDomain}`;
      const proxyResponse = await fetch(targetUrl, {
        method: 'GET',
        mode: 'no-cors'
      }).catch(() => null);

      // Query real DNS records via Cloudflare DoH
      const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const dnsData = await dnsResponse.json();
      const aRecords = dnsData.Answer || [];
      const resolvedIp = aRecords.length > 0 ? aRecords[0].data : 'Could not resolve';

      // Query TXT records for SPF check
      const txtResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=TXT`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const txtData = await txtResponse.json();
      const txtRecords = txtData.Answer || [];
      const hasSPF = txtRecords.some(r => r.data && r.data.toLowerCase().includes('v=spf1'));

      // Query DMARC
      const dmarcResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${cleanDomain}&type=TXT`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const dmarcData = await dmarcResponse.json();
      const dmarcRecords = dmarcData.Answer || [];
      const hasDMARC = dmarcRecords.some(r => r.data && r.data.toLowerCase().includes('v=dmarc1'));

      let vulnsCount = 0;
      if (!hasSPF) vulnsCount++;
      if (!hasDMARC) vulnsCount++;

      setTryResult({
        domain: cleanDomain,
        ip: resolvedIp,
        ssl: 'Query the full scan for TLS details',
        headers: {
          spf: hasSPF ? 'CONFIGURED (SPF record found)' : 'MISSING (No SPF record — email spoofing risk)',
          dmarc: hasDMARC ? 'CONFIGURED (DMARC policy found)' : 'MISSING (No DMARC record — email spoofing risk)',
        },
        dnsRecords: `${aRecords.length} A records, ${txtRecords.length} TXT records`,
        vulnsCount: vulnsCount,
        suggestion: 'Ownership verification is required to run full header, SSL, and dependency scans.'
      });
    } catch (err) {
      setTryResult({
        domain: cleanDomain,
        ip: 'DNS resolution failed',
        ssl: 'N/A',
        headers: { error: err.message },
        dnsRecords: 'Query failed',
        vulnsCount: 0,
        suggestion: 'Could not reach the target. Verify the domain name and try again.'
      });
    }

    setTryLoading(false);
  };

  const handleAddTarget = async (e) => {
    e.preventDefault();
    if (!newTargetName) return;

    const maxTargets = orgData?.plan_tier === 'team' ? 99999 : (orgData?.plan_tier === 'starter' ? 3 : 1);
    if (targets.length >= maxTargets) {
      setUpgradeModalReason('limit_reached');
      setShowAddModal(false);
      setShowUpgradeModal(true);
      return;
    }

    const formattedName = newTargetName.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').trim();
    const token = `gz-verification-token=gz_tkn_${Math.floor(100000 + Math.random() * 900000)}`;
    const tempId = `target-${Date.now()}`;

    const newTargetObj = {
      id: tempId,
      name: formattedName,
      type: newTargetType,
      verified: false,
      verificationMethod: newTargetType === 'domain' ? 'dns' : 'oauth',
      verificationToken: token,
      signedROE: false,
      signedDate: null,
      scanStatus: 'idle',
      scanType: null,
      lastScanDate: null,
      vulnerabilitiesCount: { critical: 0, high: 0, medium: 0, low: 0 },
      vulnerabilities: []
    };

    if (supabaseClient) {
      try {
        const { data: orgs } = await supabaseClient.from('organizations').select('id').limit(1);
        const orgId = orgs?.[0]?.id;

        if (orgId) {
          const { data: inserted, error } = await supabaseClient
            .from('targets')
            .insert({
              name: formattedName,
              type: newTargetType,
              verified: false,
              verification_method: newTargetType === 'domain' ? 'dns' : 'oauth',
              verification_token: token,
              organization_id: orgId
            })
            .select();

          if (error) throw error;
          if (inserted && inserted.length > 0) {
            newTargetObj.id = inserted[0].id;
          }
        }
      } catch (err) {
        console.error("Supabase Target Insert Error: ", err.message);
      }
    }

    setTargets([...targets, newTargetObj]);
    setSelectedTargetId(newTargetObj.id);
    setNewTargetName('');
    setShowAddModal(false);
    
    setActiveVerifyTarget(newTargetObj);
    setVerificationMethod(newTargetType === 'domain' ? 'dns' : 'oauth');
  };

  const performActualVerification = async () => {
    if (!activeVerifyTarget) return;
    setIsVerifying(true);
    setRealDnsVerifyResponse(null);

    const targetId = activeVerifyTarget.id;

    try {
      const response = await fetch(`${BACKEND_URL}/api/targets/${targetId}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verificationMethod })
      });

      const result = await response.json();

      if (response.ok && result.success) {
        // Backend confirmed verification passed
        setTargets(prev => prev.map(t => {
          if (t.id === targetId) {
            return { ...t, verified: true, verificationMethod };
          }
          return t;
        }));
        setIsVerifying(false);

        const updatedTarget = { ...activeVerifyTarget, verified: true, verificationMethod };
        setActiveVerifyTarget(null);
        setLegalTarget(updatedTarget);
        setShowLegalModal(true);
      } else {
        // Backend said verification failed
        setIsVerifying(false);
        setRealDnsVerifyResponse({
          success: false,
          message: result.message || result.error || 'Verification failed. Please check your configuration and try again.',
          recordsFound: result.recordsRead || result.contentPreview || ''
        });
      }
    } catch (err) {
      setIsVerifying(false);
      setRealDnsVerifyResponse({
        success: false,
        message: `Network error contacting verification server: ${err.message}`
      });
    }
  };

  // forceVerifyBypass removed to enforce strict legal authorization and ownership checks.

  const handleSignROE = async (e) => {
    e.preventDefault();
    if (!roeAccept || !roeName || !roeCompany || !legalTarget) return;
    const targetId = legalTarget.id;

    if (supabaseClient) {
      try {
        const { error } = await supabaseClient
          .from('roe_signatures')
          .insert({
            target_id: targetId,
            signer_name: roeName,
            signer_company: roeCompany,
            ip_address: '127.0.0.1'
          });
        if (error) throw error;
      } catch (err) {
        console.error("Supabase ROE Signature Error: ", err.message);
      }
    }

    setTargets(prev => prev.map(t => {
      if (t.id === targetId) {
        return {
          ...t,
          signedROE: true,
          signedDate: new Date().toISOString().replace('T', ' ').substring(0, 16)
        };
      }
      return t;
    }));

    setShowLegalModal(false);
    setRoeName('');
    setRoeCompany('');
    setRoeAccept(false);
    setLegalTarget(null);
    setActiveTab('scan');
  };

  const startScan = async () => {
    if (!selectedTarget || !selectedTarget.verified || !selectedTarget.signedROE || isScanning) return;
    setIsScanning(true);
    setConsoleLogs([]);
    setActiveTab('scan');
    
    setTargets(prev => prev.map(t => {
      if (t.id === selectedTarget.id) {
        return { ...t, scanStatus: 'running' };
      }
      return t;
    }));

    try {
      // Call the real backend scan API
      const response = await fetch(`${BACKEND_URL}/api/targets/${selectedTarget.id}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanType: scanTypeSelection })
      });

      const data = await response.json();

      if (!response.ok) {
        setConsoleLogs(prev => [...prev, `[ERROR] ${data.error || 'Scan request rejected by backend'}`]);
        setIsScanning(false);
        setTargets(prev => prev.map(t => {
          if (t.id === selectedTarget.id) return { ...t, scanStatus: 'idle' };
          return t;
        }));
        return;
      }

      const jobId = data.jobId;
      setConsoleLogs(prev => [...prev, `[INFO] Scan job ${jobId} initiated. Connecting to live telemetry stream...`]);

      // Connect to the SSE stream for real-time scan logs
      const eventSource = new EventSource(`${BACKEND_URL}/api/scans/${jobId}/stream`);

      eventSource.onmessage = (event) => {
        try {
          const entry = JSON.parse(event.data);

          // Check if scan completed
          if (entry.type === 'complete') {
            eventSource.close();
            setIsScanning(false);
            const scanDate = new Date().toISOString().replace('T', ' ').substring(0, 16);
            const result = entry.result;

            if (result && result.findings && result.findings.length > 0) {
              // Map backend findings to frontend format
              const mappedVulns = result.findings.map((f, idx) => ({
                id: f.id || `vuln-${Date.now()}-${idx}`,
                title: f.title,
                severity: f.severity,
                category: f.category,
                description: f.description,
                impact: f.impact,
                solution: f.solution,
                remediationType: f.remediationType || 'config',
                remediated: f.remediated || false,
                fileName: f.fileName,
                originalCode: f.originalCode || '# Not available',
                fixedCode: f.fixedCode || '# See solution guidance',
                chatHistory: [
                  { sender: 'analyst', text: `I found ${f.title}. ${f.solution}` }
                ]
              }));

              const counts = { critical: 0, high: 0, medium: 0, low: 0 };
              mappedVulns.forEach(v => { if (!v.remediated) counts[v.severity]++; });

              setTargets(prev => prev.map(t => {
                if (t.id === selectedTarget.id) {
                  return {
                    ...t,
                    scanStatus: 'completed',
                    scanType: scanTypeSelection,
                    lastScanDate: scanDate,
                    vulnerabilitiesCount: counts,
                    vulnerabilities: mappedVulns
                  };
                }
                return t;
              }));

              setSelectedVulnId(mappedVulns[0].id);
              setTimeout(() => setActiveTab('findings'), 1000);
            } else {
              setTargets(prev => prev.map(t => {
                if (t.id === selectedTarget.id) {
                  return { ...t, scanStatus: 'completed', lastScanDate: scanDate };
                }
                return t;
              }));
            }
            return;
          }

          // Regular log entry
          if (entry.message) {
            setConsoleLogs(prev => [...prev, entry.message]);
          }
        } catch (parseErr) {
          // Ignore parse errors on SSE data
        }
      };

      eventSource.onerror = () => {
        eventSource.close();
        setIsScanning(false);
        setConsoleLogs(prev => [...prev, '[ERROR] Lost connection to scan telemetry stream.']);
        setTargets(prev => prev.map(t => {
          if (t.id === selectedTarget.id) return { ...t, scanStatus: 'idle' };
          return t;
        }));
      };

    } catch (err) {
      setConsoleLogs(prev => [...prev, `[ERROR] Backend connection failed: ${err.message}`]);
      setConsoleLogs(prev => [...prev, '[INFO] Ensure the backend is running on ' + BACKEND_URL]);
      setIsScanning(false);
      setTargets(prev => prev.map(t => {
        if (t.id === selectedTarget.id) return { ...t, scanStatus: 'idle' };
        return t;
      }));
    }
  };

  const applyRemediation = async (vulnId) => {
    if (supabaseClient) {
      try {
        const { error } = await supabaseClient
          .from('vulnerabilities')
          .update({ remediated: true })
          .eq('id', vulnId);
        if (error) throw error;
      } catch (err) {
        console.error("Supabase remediation status update failed: ", err.message);
      }
    }

    setTargets(prev => prev.map(t => {
      if (t.id === selectedTarget.id) {
        const updatedVulns = t.vulnerabilities.map(v => {
          if (v.id === vulnId) {
            return { ...v, remediated: true };
          }
          return v;
        });

        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        updatedVulns.forEach(v => {
          if (!v.remediated) {
            counts[v.severity]++;
          }
        });

        return {
          ...t,
          vulnerabilities: updatedVulns,
          vulnerabilitiesCount: counts
        };
      }
      return t;
    }));
  };

  const handleChatMessageSubmit = async (e) => {
    e.preventDefault();
    if (!chatMessageInput.trim() || !selectedVuln) return;

    const userText = chatMessageInput;
    const vulnId = selectedVuln.id;
    setChatMessageInput('');

    if (supabaseClient) {
      try {
        await supabaseClient
          .from('chat_messages')
          .insert({
            vulnerability_id: vulnId,
            sender: 'user',
            message: userText
          });
      } catch (err) {
        console.error("Supabase chat message insert error: ", err.message);
      }
    }

    setTargets(prev => prev.map(t => {
      if (t.id === selectedTarget.id) {
        const updatedVulns = t.vulnerabilities.map(v => {
          if (v.id === vulnId) {
            return {
              ...v,
              chatHistory: [...v.chatHistory, { sender: 'user', text: userText }]
            };
          }
          return v;
        });
        return { ...t, vulnerabilities: updatedVulns };
      }
      return t;
    }));

    setTimeout(async () => {
      let analystResponse = '';
      const lowercaseUserText = userText.toLowerCase();

      if (lowercaseUserText.includes('false positive') || lowercaseUserText.includes('false-positive')) {
        analystResponse = "Based on our passive signature mapping and package parse, this exact vulnerability version was isolated. If you have backported a manual patch, let us know and you can mark it as resolved or trigger a scan reload.";
      } else if (lowercaseUserText.includes('exploit') || lowercaseUserText.includes('exploit code') || lowercaseUserText.includes('how to test')) {
        if (selectedVuln.category === 'Dependency SCA') {
          analystResponse = "For lodash CVE-2020-8203, an attacker exploits this by sending JSON requests containing properties like '__proto__.constructor.prototype.auth = true'. If your backend merges requests unsafely, this payload pollutes global prototypes.";
        } else if (selectedVuln.category === 'Cloud Posture') {
          analystResponse = "To test this, run: 'aws s3 api get-bucket-policy --bucket geolzen-static-assets --no-sign-request'. If it returns the policy JSON instead of an access denied error, the bucket represents public exposure.";
        } else {
          analystResponse = "To verify this manually, query the headers using curl: 'curl -I https://" + selectedTarget.name + "'. Check for the absence of Content-Security-Policy in the returned header stack.";
        }
      } else if (lowercaseUserText.includes('manually') || lowercaseUserText.includes('alternative') || lowercaseUserText.includes('manual')) {
        analystResponse = "If you want to solve this without our auto-patch, you can follow the 'Proposed Resolution' guidelines above. For code files, verify the correct version is referenced in your lock files, then run clean installs.";
      } else {
        analystResponse = `I understand your question about "${selectedVuln.title}". We suggest applying our generated diff patch as it is fully tested. Let me know if you would like me to explain the remediation logic step-by-step.`;
      }

      if (supabaseClient) {
        try {
          await supabaseClient
            .from('chat_messages')
            .insert({
              vulnerability_id: vulnId,
              sender: 'analyst',
              message: analystResponse
            });
        } catch (err) {
          console.error("Supabase chat message insert error: ", err.message);
        }
      }

      setTargets(prev => prev.map(t => {
        if (t.id === selectedTarget.id) {
          const updatedVulns = t.vulnerabilities.map(v => {
            if (v.id === vulnId) {
              return {
                ...v,
                chatHistory: [...v.chatHistory, { sender: 'analyst', text: analystResponse }]
              };
            }
            return v;
          });
          return { ...t, vulnerabilities: updatedVulns };
        }
        return t;
      }));
    }, 1200);
  };

  const downloadPDFReport = () => {
    if (!selectedTarget) return;
    const element = document.createElement('a');
    const content = `
=========================================
      GEOLZEN SECURITY SCAN REPORT
=========================================
Target: ${selectedTarget.name} (${selectedTarget.type.toUpperCase()})
Scan Date: ${selectedTarget.lastScanDate || 'N/A'}
Compliance Status: Approved (ROE Signed on ${selectedTarget.signedDate})
-----------------------------------------
Vulnerability Count Summary:
  Critical: ${selectedTarget.vulnerabilitiesCount.critical}
  High: ${selectedTarget.vulnerabilitiesCount.high}
  Medium: ${selectedTarget.vulnerabilitiesCount.medium}
  Low: ${selectedTarget.vulnerabilitiesCount.low}
-----------------------------------------

DETAILED FINDINGS:
${selectedTarget.vulnerabilities.map((v, i) => `
[${i+1}] ${v.title}
    Severity: ${v.severity.toUpperCase()}
    Category: ${v.category}
    Remediation Status: ${v.remediated ? 'REMEDIATED / APPLIED' : 'PENDING'}
    Description: ${v.description}
    Impact: ${v.impact}
    Fix Suggestion: ${v.solution}
    File Path: ${v.fileName}
`).join('\n')}

=========================================
Generated by Geolzen Security Platform
    https://geolzen.io
=========================================
    `;
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `geolzen-report-${selectedTarget.name}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const getTotalVulns = (severity) => {
    return targets.reduce((acc, t) => acc + (t.vulnerabilitiesCount[severity] || 0), 0);
  };

  const getRemediationRate = () => {
    let total = 0;
    let resolved = 0;
    targets.forEach(t => {
      t.vulnerabilities.forEach(v => {
        total++;
        if (v.remediated) resolved++;
      });
    });
    if (total === 0) return 100;
    return Math.round((resolved / total) * 100);
  };

  const renderCodeDiff = (original, fixed) => {
    const oLines = original.split('\n');
    const fLines = fixed.split('\n');
    
    return (
      <div className="diff-container">
        <div className="diff-panel">
          <div className="diff-header">Current Configuration</div>
          <pre className="diff-content">
            {oLines.map((line, idx) => {
              const cleanLine = line.trim();
              const isChanged = !fLines.some(fLine => fLine.trim() === cleanLine);
              return (
                <code key={idx} className={isChanged ? "diff-line-removed" : "diff-line-normal"}>
                  {line}
                </code>
              );
            })}
          </pre>
        </div>
        <div className="diff-panel">
          <div className="diff-header">Geolzen Proposed Fix</div>
          <pre className="diff-content">
            {fLines.map((line, idx) => {
              const cleanLine = line.trim();
              const isChanged = !oLines.some(oLine => oLine.trim() === cleanLine);
              return (
                <code key={idx} className={isChanged ? "diff-line-added" : "diff-line-normal"}>
                  {line}
                </code>
              );
            })}
          </pre>
        </div>
      </div>
    );
  };

  // Switch tab utility that collapses the mobile menu drawer
  const selectTab = (tabName) => {
    setActiveTab(tabName);
    setIsMobileMenuOpen(false);
  };

  // 1. PUBLIC LANDING PAGE
  if (!isAuthenticated && !showAuthGate) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#060609' }}>
        
        {/* Navigation bar */}
        <header style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', backdropFilter: 'blur(12px)', sticky: 'top', backgroundColor: 'rgba(6, 6, 9, 0.9)', zIndex: 10 }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '18px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} className="header-container">
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ background: 'linear-gradient(135deg, var(--accent-orange), var(--accent-orange-bright))', padding: 8, borderRadius: 8 }}>
                <Shield size={24} color="#060609" strokeWidth={2.5} />
              </div>
              <span style={{ fontSize: '1.4rem', fontWeight: 800, background: 'linear-gradient(90deg, var(--accent-orange), var(--accent-orange-bright))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>GEOLZEN</span>
            </div>
            
            <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
              <button 
                onClick={() => { setAuthMode('login'); setShowAuthGate(true); }}
                className="glow-btn-outline" 
                style={{ padding: '8px 18px', fontSize: '0.85rem' }}
              >
                Sign In
              </button>
              <button 
                onClick={() => { setAuthMode('signup'); setShowAuthGate(true); }}
                className="glow-btn" 
                style={{ padding: '8px 18px', fontSize: '0.85rem' }}
              >
                Get Started
              </button>
            </div>
          </div>
        </header>

        {/* Hero Area */}
        <main style={{ flex: 1 }}>
          <section className="landing-hero">
            <h1 className="landing-title">Autonomous Attack Surface Management & Remediation</h1>
            <p style={{ fontSize: '1.2rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 40 }}>
              Verify ownership in seconds, launch automated scanning (DAST, SCA, Network, Cloud), and apply security patches via auto-generated pull requests. Safe, compliant, and developer-first.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', gap: 16 }}>
              <button onClick={() => { setAuthMode('signup'); setShowAuthGate(true); }} className="glow-btn" style={{ padding: '14px 28px', fontSize: '1rem' }}>
                Start Free Trial <ArrowRight size={18} />
              </button>
              <a href="#demo-scanner" className="glow-btn-outline" style={{ padding: '14px 28px', fontSize: '1rem' }}>
                Try Live Recon
              </a>
            </div>

            {/* Quick Demo Scanner Widget */}
            <div id="demo-scanner" className="try-scanner-widget" style={{ marginTop: 60 }}>
              <h3 style={{ margin: '0 0 8px 0', fontWeight: 700, fontSize: '1.15rem' }}>Run a Free Passive Recon Check</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 20px 0' }}>Enter a domain you want to test. Direct public check on DNS, open ports, and HTTPS headers.</p>
              
              <form onSubmit={runLandingScanner}>
                <div className="try-scanner-input-group">
                  <input 
                    type="text" 
                    required 
                    placeholder="example.com" 
                    value={tryUrl}
                    onChange={(e) => setTryUrl(e.target.value)}
                  />
                  <button type="submit" className="glow-btn" style={{ padding: '8px 20px' }}>
                    {tryLoading ? <RefreshCw size={16} className="animate-spin" /> : 'Scan Now'}
                  </button>
                </div>
              </form>

              {/* Try Results */}
              {tryResult && (
                <div style={{
                  marginTop: 20,
                  textAlign: 'left',
                  backgroundColor: '#040407',
                  border: '1px solid rgba(255, 107, 0, 0.15)',
                  borderRadius: 10,
                  padding: 16,
                  fontSize: '0.85rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: 10, marginBottom: 12 }}>
                    <strong>Report: {tryResult.domain}</strong>
                    <span style={{ color: 'var(--color-medium)' }}>{tryResult.vulnsCount} Warnings Isolated</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, color: 'var(--text-secondary)' }}>
                    <div>IP Endpoint: <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{tryResult.ip}</span></div>
                    <div>DNS Records: <span style={{ color: '#fff' }}>{tryResult.dnsRecords}</span></div>
                    <div>SSL/TLS: <span style={{ color: 'var(--text-secondary)' }}>{tryResult.ssl}</span></div>
                    
                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.03)', paddingTop: 8, marginTop: 4 }}>
                      {tryResult.headers.spf && (
                        <div style={{ color: tryResult.headers.spf.startsWith('CONFIGURED') ? 'var(--color-success)' : 'var(--color-high)', marginBottom: 4 }}>
                          {tryResult.headers.spf.startsWith('CONFIGURED') ? '✅' : '⚠️'} SPF: {tryResult.headers.spf}
                        </div>
                      )}
                      {tryResult.headers.dmarc && (
                        <div style={{ color: tryResult.headers.dmarc.startsWith('CONFIGURED') ? 'var(--color-success)' : 'var(--color-high)', marginBottom: 4 }}>
                          {tryResult.headers.dmarc.startsWith('CONFIGURED') ? '✅' : '⚠️'} DMARC: {tryResult.headers.dmarc}
                        </div>
                      )}
                      {tryResult.headers.error && (
                        <div style={{ color: 'var(--color-critical)' }}>❌ {tryResult.headers.error}</div>
                      )}
                    </div>
                  </div>

                  <div style={{ marginTop: 16, borderTop: '1px dashed rgba(255,255,255,0.1)', paddingTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{tryResult.suggestion}</span>
                    <button 
                      onClick={() => { setAuthMode('signup'); setShowAuthGate(true); }}
                      className="glow-btn"
                      style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                    >
                      Verify Domain & Auto-Fix
                    </button>
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* Value Propositions */}
          <section style={{ backgroundColor: 'rgba(28, 29, 40, 0.2)', borderTop: '1px solid rgba(255,255,255,0.02)', padding: '60px 24px' }}>
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
              <h2 style={{ textAlign: 'center', marginBottom: 40, fontSize: '2rem', fontWeight: 800 }}>Platform Foundations</h2>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 24 }}>
                <div className="glass-panel" style={{ padding: 24 }}>
                  <div style={{ background: 'rgba(255, 107, 0, 0.05)', border: '1px solid rgba(255, 107, 0, 0.2)', width: 44, height: 44, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16 }}>
                    <Lock size={20} color="var(--accent-orange)" />
                  </div>
                  <h3 style={{ fontSize: '1.2rem', margin: '0 0 10px 0', fontWeight: 700 }}>Airtight Verification</h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5, margin: 0 }}>
                    We query nameservers live via DNS-over-HTTPS. Direct integration guarantees scans only target systems you own, protecting you legally.
                  </p>
                </div>

                <div className="glass-panel" style={{ padding: 24 }}>
                  <div style={{ background: 'rgba(255, 107, 0, 0.05)', border: '1px solid rgba(255, 107, 0, 0.2)', width: 44, height: 44, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16 }}>
                    <GitPullRequest size={20} color="var(--accent-orange)" />
                  </div>
                  <h3 style={{ fontSize: '1.2rem', margin: '0 0 10px 0', fontWeight: 700 }}>Auto-Remediation (PRs)</h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5, margin: 0 }}>
                    Do not just read CVE logs. Geolzen generates git diffs, S3 policy patches, and HTTP config rewrites you can apply in one click.
                  </p>
                </div>

                <div className="glass-panel" style={{ padding: 24 }}>
                  <div style={{ background: 'rgba(255, 107, 0, 0.05)', border: '1px solid rgba(255, 107, 0, 0.2)', width: 44, height: 44, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16 }}>
                    <MessageSquare size={20} color="var(--accent-orange)" />
                  </div>
                  <h3 style={{ fontSize: '1.2rem', margin: '0 0 10px 0', fontWeight: 700 }}>Security Analyst Support</h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5, margin: 0 }}>
                    Query our security analyst chat directly on vulnerabilities. Ask details on testing vectors, impact, and patch validation.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Pricing Plans */}
          <section style={{ padding: '60px 24px' }}>
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
              <h2 style={{ textAlign: 'center', marginBottom: 12, fontSize: '2rem', fontWeight: 800 }}>Simple, Predictable Tiers</h2>
              <p style={{ textAlign: 'center', color: 'var(--text-secondary)', marginBottom: 40 }}>Choose a plan scaled to your infrastructure coverage.</p>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 20 }}>
                <div className="glass-panel" style={{ padding: 28, display: 'flex', flexDirection: 'column' }}>
                  <h4 style={{ margin: 0, color: 'var(--text-secondary)' }}>Free</h4>
                  <div style={{ fontSize: '2rem', fontWeight: 800, margin: '12px 0' }}>$0</div>
                  <ul style={{ paddingLeft: 18, fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8, flex: 1, margin: '0 0 20px 0' }}>
                    <li>1 Verified Domain</li>
                    <li>Passive Recon checks</li>
                    <li>Monthly Schedule</li>
                  </ul>
                  <button onClick={() => { setAuthMode('signup'); setShowAuthGate(true); }} className="glow-btn-outline" style={{ width: '100%' }}>Register Free</button>
                </div>

                <div className="glass-panel" style={{ padding: 28, display: 'flex', flexDirection: 'column', border: '1px solid var(--accent-orange)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h4 style={{ margin: 0, color: 'var(--accent-orange)' }}>Starter</h4>
                    <span style={{ fontSize: '0.7rem', padding: '2px 8px', borderRadius: 4, backgroundColor: 'rgba(255, 107, 0, 0.1)', color: 'var(--accent-orange)' }}>POPULAR</span>
                  </div>
                  <div style={{ fontSize: '2rem', fontWeight: 800, margin: '12px 0' }}>$49<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/mo</span></div>
                  <ul style={{ paddingLeft: 18, fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8, flex: 1, margin: '0 0 20px 0' }}>
                    <li>3 Targets (Domains/Repos)</li>
                    <li>Weekly active DAST scans</li>
                    <li>Dependency SCA audits</li>
                    <li>PDF Report downloads</li>
                  </ul>
                  <button onClick={() => handleCheckout('starter', 49)} className="glow-btn" style={{ width: '100%' }}>Choose Starter</button>
                </div>

                <div className="glass-panel" style={{ padding: 28, display: 'flex', flexDirection: 'column' }}>
                  <h4 style={{ margin: 0, color: 'var(--text-secondary)' }}>Team</h4>
                  <div style={{ fontSize: '2rem', fontWeight: 800, margin: '12px 0' }}>$299<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/mo</span></div>
                  <ul style={{ paddingLeft: 18, fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8, flex: 1, margin: '0 0 20px 0' }}>
                    <li>Unlimited targets</li>
                    <li>Continuous monitoring scans</li>
                    <li>Auto-Fix pull request creation</li>
                    <li>Slack / Jira ticket alerts</li>
                  </ul>
                  <button onClick={() => handleCheckout('team', 299)} className="glow-btn-outline" style={{ width: '100%' }}>Choose Team</button>
                </div>
              </div>
            </div>
          </section>
        </main>

        <footer style={{ borderTop: '1px solid rgba(255,255,255,0.03)', padding: '20px 0', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 20 }}>
            <span>© 2026 Geolzen Inc.</span>
            <button 
              onClick={() => setShowPrivacyModal(true)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', textDecoration: 'underline' }}
            >
              Privacy Policy
            </button>
          </div>
        </footer>

        {/* Global Privacy Modal */}
        {showPrivacyModal && (
          <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)',
            display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 2000
          }}>
            <div className="glass-panel" style={{ width: '550px', maxHeight: '80vh', display: 'flex', flexDirection: 'column', padding: 28 }}>
              <h3 style={{ margin: '0 0 16px 0', fontSize: '1.3rem', fontWeight: 800 }}>Geolzen Privacy Policy</h3>
              
              <div style={{
                flex: 1, overflowY: 'auto', padding: 16, backgroundColor: '#040407', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 8, fontSize: '0.8rem', lineHeight: 1.6, color: 'var(--text-secondary)', marginBottom: 20
              }}>
                <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>1. Data Collection Scopes</h4>
                <p style={{ margin: '0 0 12px 0' }}>
                  Geolzen collects target domain URLs, DNS configurations, dependency library structures, and compliance logs (names, company titles, signature timestamps, and source IP addresses).
                </p>
                <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>2. Data Utilization Rules</h4>
                <p style={{ margin: '0 0 12px 0' }}>
                  Data is processed exclusively to run security audits, compile side-by-side git diff configurations, execute auto-remediations, and tune the analyst support copilot responses.
                </p>
                <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>3. Supabase Storage & Security</h4>
                <p style={{ margin: '0 0 12px 0' }}>
                  Operations details are stored in Supabase PostgreSQL databases with Row-Level Security (RLS). Users can only access metrics linked to their verified organization workspace.
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                <button 
                  onClick={() => setShowPrivacyModal(false)}
                  className="glow-btn"
                >
                  Close Policy
                </button>
              </div>
            </div>
          </div>
        )}

      </div>
    );
  }

  // 2. AUTHENTICATION GATEWAY (Mandatory Consent + Supabase API binding)
  if (!isAuthenticated && showAuthGate) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', backgroundColor: '#060609', padding: '0 24px' }}>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, cursor: 'pointer' }} onClick={() => { setShowAuthGate(false); setAuthMessage(null); }}>
          <div style={{ background: 'linear-gradient(135deg, var(--accent-orange), var(--accent-orange-bright))', padding: 8, borderRadius: 8 }}>
            <Shield size={24} color="#060609" strokeWidth={2.5} />
          </div>
          <span style={{ fontSize: '1.4rem', fontWeight: 800, background: 'linear-gradient(90deg, var(--accent-orange), var(--accent-orange-bright))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>GEOLZEN</span>
        </div>

        <div className="auth-card">
          <div className="auth-tabs">
            <button 
              type="button"
              className={`auth-tab-btn ${authMode === 'login' ? 'active' : ''}`}
              onClick={() => { setAuthMode('login'); setAuthMessage(null); }}
            >
              Sign In
            </button>
            <button 
              type="button"
              className={`auth-tab-btn ${authMode === 'signup' ? 'active' : ''}`}
              onClick={() => { setAuthMode('signup'); setAuthMessage(null); }}
            >
              Sign Up
            </button>
          </div>

          {authMessage && (
            <div style={{
              padding: 10,
              borderRadius: 6,
              fontSize: '0.8rem',
              marginBottom: 16,
              backgroundColor: authMessage.type === 'error' ? 'rgba(255, 60, 60, 0.1)' : 'rgba(0, 230, 118, 0.1)',
              border: authMessage.type === 'error' ? '1px solid var(--color-critical)' : '1px solid var(--color-success)',
              color: authMessage.type === 'error' ? 'var(--color-critical)' : 'var(--color-success)'
            }}>
              {authMessage.text}
            </div>
          )}

          <form onSubmit={handleAuthSubmit}>
            {(authMode === 'signup' || authMode === 'login') && (
              <>
                {authMode === 'signup' && (
              <>
                <div className="form-group">
                  <label>Full Name</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="Alice Smith" 
                    value={authFullNameInput}
                    onChange={(e) => setAuthFullNameInput(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label>Company / Organization Name</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="Acme Security Corp" 
                    value={authOrgInput}
                    onChange={(e) => setAuthOrgInput(e.target.value)}
                  />
                </div>
              </>
            )}

            <div className="form-group">
              <label>Work Email Address</label>
              <input 
                type="email" 
                required 
                placeholder="dev@company.com" 
                value={authEmailInput}
                onChange={(e) => setAuthEmailInput(e.target.value)}
              />
            </div>

            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <label style={{ margin: 0 }}>Password</label>
                {authMode === 'login' && (
                  <button type="button" onClick={handleForgotPassword} style={{ background: 'none', border: 'none', color: 'var(--accent-orange)', fontSize: '0.75rem', padding: 0, cursor: 'pointer' }}>
                    Forgot Password?
                  </button>
                )}
              </div>
              <div style={{ position: 'relative' }}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  required 
                  placeholder="••••••••" 
                  value={authPasswordInput}
                  onChange={(e) => setAuthPasswordInput(e.target.value)}
                  style={{ width: '100%', paddingRight: '40px' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '10px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

              </>
            )}

            {authMode === 'reset_otp' && (
              <div className="form-group">
                <label>Enter 8-Digit OTP from Email</label>
                <input 
                  type="text" 
                  required 
                  placeholder="12345678" 
                  value={authOtpInput}
                  onChange={(e) => setAuthOtpInput(e.target.value)}
                  maxLength={8}
                />
              </div>
            )}

            {authMode === 'new_password' && (
              <div className="form-group">
                <label>Set New Password</label>
                <div style={{ position: 'relative' }}>
                  <input 
                    type={showPassword ? "text" : "password"} 
                    required 
                    placeholder="••••••••" 
                    value={authNewPasswordInput}
                    onChange={(e) => setAuthNewPasswordInput(e.target.value)}
                    style={{ width: '100%', paddingRight: '40px' }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      position: 'absolute',
                      right: '10px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-muted)',
                      cursor: 'pointer',
                      padding: 0,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            )}

            <button 
              type="submit" 
              className="glow-btn" 
              style={{ width: '100%', marginTop: 24 }}
              disabled={authLoading || (authMode === 'signup' && !privacyAgreed)}
            >
              {authLoading ? <RefreshCw size={16} className="animate-spin" /> : 
                authMode === 'login' ? 'Sign In to Console' : 
                authMode === 'reset_otp' ? 'Verify Code' : 
                authMode === 'new_password' ? 'Set Password' : 
                'Initialize Account'}
            </button>
          </form>



          <button 
            onClick={() => { setShowAuthGate(false); setAuthMessage(null); }}
            className="glow-btn-outline"
            style={{ width: '100%', border: 'none', background: 'transparent', color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 12 }}
          >
            ← Back to Home Page
          </button>
        </div>
      </div>
    );
  }

  // 3. SECURE AUTHENTICATED DASHBOARD
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Top Navbar */}
      <header style={{
        borderBottom: '1px solid rgba(255, 107, 0, 0.1)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        backgroundColor: 'rgba(6, 6, 9, 0.9)'
      }}>
        <div style={{
          maxWidth: '1200px',
          margin: '0 auto',
          padding: '16px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }} className="header-container">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              background: 'linear-gradient(135deg, var(--accent-orange), var(--accent-orange-bright))',
              padding: 8,
              borderRadius: 8,
              boxShadow: '0 0 15px rgba(255, 107, 0, 0.3)',
              display: 'flex',
              alignItems: 'center'
            }}>
              <Shield size={24} color="#060609" strokeWidth={2.5} />
            </div>
            <div>
              <span style={{
                fontFamily: 'var(--font-sans)',
                fontWeight: 800,
                fontSize: '1.4rem',
                letterSpacing: '1px',
                background: 'linear-gradient(90deg, var(--accent-orange), var(--accent-orange-bright))',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                textShadow: '0 0 20px rgba(255, 107, 0, 0.15)'
              }}>
                GEOLZEN
              </span>
              <span style={{
                display: 'block',
                fontSize: '0.65rem',
                color: 'var(--text-secondary)',
                letterSpacing: '2px',
                textTransform: 'uppercase',
                marginTop: -4
              }}>
                Autonomous Attack Surface Platform
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            {/* Desktop Navbar Row */}
            <nav className="desktop-nav">
              <button 
                onClick={() => selectTab('overview')}
                className={`glow-btn-outline ${activeTab === 'overview' ? 'active' : ''}`}
                style={{
                  padding: '6px 12px', 
                  fontSize: '0.85rem', 
                  borderRadius: 6,
                  border: activeTab === 'overview' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                  background: activeTab === 'overview' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                  color: activeTab === 'overview' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                }}
              >
                Overview
              </button>
              <button 
                onClick={() => selectTab('targets')}
                className={`glow-btn-outline ${activeTab === 'targets' ? 'active' : ''}`}
                style={{
                  padding: '6px 12px', 
                  fontSize: '0.85rem', 
                  borderRadius: 6,
                  border: activeTab === 'targets' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                  background: activeTab === 'targets' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                  color: activeTab === 'targets' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                }}
              >
                Targets ({targets.length})
              </button>
              <button 
                onClick={() => selectTab('scan')}
                className={`glow-btn-outline ${activeTab === 'scan' ? 'active' : ''}`}
                style={{
                  padding: '6px 12px', 
                  fontSize: '0.85rem', 
                  borderRadius: 6,
                  border: activeTab === 'scan' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                  background: activeTab === 'scan' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                  color: activeTab === 'scan' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                }}
              >
                Scan Console {isScanning && <RefreshCw size={12} className="animate-spin" style={{ display: 'inline', marginLeft: 4 }} />}
              </button>
              <button 
                onClick={() => selectTab('findings')}
                className={`glow-btn-outline ${activeTab === 'findings' ? 'active' : ''}`}
                style={{
                  padding: '6px 12px', 
                  fontSize: '0.85rem', 
                  borderRadius: 6,
                  border: activeTab === 'findings' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                  background: activeTab === 'findings' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                  color: activeTab === 'findings' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                }}
              >
                Findings ({selectedTarget?.vulnerabilities.filter(v => !v.remediated).length || 0})
              </button>
              <button 
                onClick={() => selectTab('settings')}
                className={`glow-btn-outline ${activeTab === 'settings' ? 'active' : ''}`}
                style={{
                  padding: '6px 12px', 
                  fontSize: '0.85rem', 
                  borderRadius: 6,
                  border: activeTab === 'settings' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                  background: activeTab === 'settings' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                  color: activeTab === 'settings' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                }}
              >
                Settings
              </button>
            </nav>

            {/* Mobile Hamburger menu Button */}
            <button 
              className="mobile-menu-trigger" 
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              style={{ zIndex: 1100 }}
              aria-label="Toggle Navigation Menu"
            >
              {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>

            <button 
              onClick={() => { localStorage.removeItem('geolzen_auth'); setIsAuthenticated(false); setAuthMessage(null); setPrivacyAgreed(false); }}
              className="glow-btn-outline desktop-nav"
              style={{ padding: '6px 12px', fontSize: '0.8rem', borderColor: 'var(--text-muted)', color: 'var(--text-muted)' }}
            >
              Logout
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu Drawer Overlay */}
        <div className={`mobile-nav-overlay ${isMobileMenuOpen ? 'open' : ''}`}>
          <button 
            onClick={() => selectTab('overview')}
            className={`glow-btn-outline ${activeTab === 'overview' ? 'active' : ''}`}
            style={{
              width: '100%',
              justifyContent: 'flex-start',
              border: activeTab === 'overview' ? '1px solid var(--accent-orange)' : '1px solid transparent',
              background: activeTab === 'overview' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
              color: activeTab === 'overview' ? 'var(--accent-orange)' : 'var(--text-secondary)'
            }}
          >
            Overview
          </button>
          <button 
            onClick={() => selectTab('targets')}
            className={`glow-btn-outline ${activeTab === 'targets' ? 'active' : ''}`}
            style={{
              width: '100%',
              justifyContent: 'flex-start',
              border: activeTab === 'targets' ? '1px solid var(--accent-orange)' : '1px solid transparent',
              background: activeTab === 'targets' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
              color: activeTab === 'targets' ? 'var(--accent-orange)' : 'var(--text-secondary)'
            }}
          >
            Targets ({targets.length})
          </button>
          <button 
            onClick={() => selectTab('scan')}
            className={`glow-btn-outline ${activeTab === 'scan' ? 'active' : ''}`}
            style={{
              width: '100%',
              justifyContent: 'flex-start',
              border: activeTab === 'scan' ? '1px solid var(--accent-orange)' : '1px solid transparent',
              background: activeTab === 'scan' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
              color: activeTab === 'scan' ? 'var(--accent-orange)' : 'var(--text-secondary)'
            }}
          >
            Scan Console {isScanning && <RefreshCw size={12} className="animate-spin" style={{ display: 'inline', marginLeft: 4 }} />}
          </button>
          <button 
            onClick={() => selectTab('findings')}
            className={`glow-btn-outline ${activeTab === 'findings' ? 'active' : ''}`}
            style={{
              width: '100%',
              justifyContent: 'flex-start',
              border: activeTab === 'findings' ? '1px solid var(--accent-orange)' : '1px solid transparent',
              background: activeTab === 'findings' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
              color: activeTab === 'findings' ? 'var(--accent-orange)' : 'var(--text-secondary)'
            }}
          >
            Findings ({selectedTarget?.vulnerabilities.filter(v => !v.remediated).length || 0})
          </button>
          <button 
            onClick={() => selectTab('settings')}
            className={`glow-btn-outline ${activeTab === 'settings' ? 'active' : ''}`}
            style={{
              width: '100%',
              justifyContent: 'flex-start',
              border: activeTab === 'settings' ? '1px solid var(--accent-orange)' : '1px solid transparent',
              background: activeTab === 'settings' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
              color: activeTab === 'settings' ? 'var(--accent-orange)' : 'var(--text-secondary)'
            }}
          >
            Settings
          </button>
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 12, marginTop: 4 }}>
            <button 
              onClick={() => { localStorage.removeItem('geolzen_auth'); setIsAuthenticated(false); setAuthMessage(null); setPrivacyAgreed(false); setIsMobileMenuOpen(false); }}
              className="glow-btn-danger"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              Logout Account
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ flex: 1, width: '100%', maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
        
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h1 style={{ fontSize: '2.2rem', margin: '0 0 8px 0', fontWeight: 800 }}>
                Welcome back, {userProfile.fullName}!
              </h1>
              <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
                Protecting <strong>{userProfile.orgName}</strong>'s infrastructure attack surface and package dependencies.
              </p>
            </div>

            {/* Syncing database indicator */}
            {isDbsyncing && (
              <div style={{
                marginBottom: 20,
                padding: 10,
                borderRadius: 6,
                backgroundColor: 'rgba(255, 107, 0, 0.05)',
                border: '1px solid rgba(255, 107, 0, 0.15)',
                color: 'var(--accent-orange)',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}>
                <RefreshCw size={14} className="animate-spin" />
                <span>Synchronizing database records from Supabase tables...</span>
              </div>
            )}

            {/* Stats row */}
            <div className="dashboard-stats" style={{ marginBottom: 32 }}>
              <div className="glass-panel">
                <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: 1 }}>Total Targets</span>
                <div style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: 8, display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
                  {targets.length}
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>({targets.filter(t => t.verified).length} verified)</span>
                </div>
              </div>

              <div className="glass-panel" style={{ borderLeft: '3px solid var(--color-critical)' }}>
                <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: 1 }}>Critical Vulns</span>
                <div style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--color-critical)', marginTop: 8 }}>
                  {getTotalVulns('critical')}
                </div>
              </div>

              <div className="glass-panel" style={{ borderLeft: '3px solid var(--color-high)' }}>
                <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: 1 }}>High Vulns</span>
                <div style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--color-high)', marginTop: 8 }}>
                  {getTotalVulns('high')}
                </div>
              </div>

              <div className="glass-panel" style={{ borderLeft: '3px solid var(--color-success)' }}>
                <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: 1 }}>Fix Rate</span>
                <div style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--color-success)', marginTop: 8 }}>
                  {getRemediationRate()}%
                </div>
              </div>
            </div>

            {/* Quick action + Main list split */}
            <div className="grid-layout-overview">
              
              {/* Targets List */}
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 10 }}>
                  <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700 }}>Scannable Targets</h3>
                  <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <div style={{ padding: '8px 16px', background: 'rgba(255, 107, 0, 0.1)', border: '1px solid var(--accent-orange)', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Current Plan</div>
                        <div style={{ fontWeight: 'bold', textTransform: 'capitalize' }}>{orgData?.plan_tier || 'Free'} ({targets.length}/{orgData?.plan_tier === 'team' ? '∞' : (orgData?.plan_tier === 'starter' ? 3 : 1)})</div>
                      </div>
                      {orgData?.plan_tier !== 'team' && (
                        <button onClick={() => { setUpgradeModalReason(null); setShowUpgradeModal(true); }} className="glow-btn" style={{ padding: '6px 12px', fontSize: '0.8rem' }}>Upgrade</button>
                      )}
                    </div>
                    <button 
                      onClick={() => setShowAddModal(true)}
                      className="glow-btn" 
                      style={{ padding: '8px 16px', fontSize: '0.85rem', height: 'fit-content', alignSelf: 'center' }}
                    >
                      <Plus size={16} /> Add Target
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {targets.map(target => (
                    <div 
                      key={target.id}
                      style={{
                        padding: 16,
                        border: '1px solid rgba(255,255,255,0.05)',
                        backgroundColor: 'rgba(255,255,255,0.01)',
                        borderRadius: 8,
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: 12,
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        {target.type === 'domain' ? <Globe size={20} color="var(--accent-orange)" /> : <GithubIcon size={20} color="var(--accent-orange)" />}
                        <div>
                          <span style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--text-primary)' }}>{target.name}</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>
                            {target.type} • {target.verified ? 'VERIFIED' : 'UNVERIFIED'}
                          </span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        {/* Badges of Vulns */}
                        {target.verified && target.vulnerabilities.length > 0 && (
                          <div style={{ display: 'flex', gap: 6 }}>
                            {target.vulnerabilitiesCount.critical > 0 && <span className="badge badge-critical">{target.vulnerabilitiesCount.critical}</span>}
                            {target.vulnerabilitiesCount.high > 0 && <span className="badge badge-high">{target.vulnerabilitiesCount.high}</span>}
                            {target.vulnerabilitiesCount.medium > 0 && <span className="badge badge-medium">{target.vulnerabilitiesCount.medium}</span>}
                          </div>
                        )}

                        {/* Status / Call to Action */}
                        {!target.verified ? (
                          <button 
                            className="glow-btn-outline" 
                            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                            onClick={() => {
                              setActiveVerifyTarget(target);
                              setVerificationMethod(target.type === 'domain' ? 'dns' : 'oauth');
                            }}
                          >
                            Verify Owner
                          </button>
                        ) : !target.signedROE ? (
                          <button 
                            className="glow-btn-outline" 
                            style={{ padding: '6px 12px', fontSize: '0.8rem', borderColor: 'var(--color-medium)', color: 'var(--color-medium)' }}
                            onClick={() => {
                              setLegalTarget(target);
                              setShowLegalModal(true);
                            }}
                          >
                            Sign consent
                          </button>
                        ) : target.scanStatus === 'running' ? (
                          <span style={{ fontSize: '0.8rem', color: 'var(--accent-orange)', display: 'flex', alignItems: 'center', gap: 6 }}>
                            <RefreshCw size={12} className="animate-spin" /> Scanning
                          </span>
                        ) : (
                          <button 
                            className="glow-btn-outline" 
                            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                            onClick={() => {
                              setSelectedTargetId(target.id);
                              setActiveTab('scan');
                            }}
                          >
                            Launch Scan
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Legal Framework Warning */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                <div className="glass-panel" style={{ borderLeft: '4px solid var(--accent-orange)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                    <Lock size={18} color="var(--accent-orange)" />
                    <h4 style={{ margin: 0, fontWeight: 700 }}>Legal Authorization</h4>
                  </div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 14 }}>
                    Geolzen operates strictly within authorized scopes. Before active testing commences, targets must:
                  </p>
                  <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: 18, margin: '0 0 14px 0', display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <li>Prove domain/repo DNS or OAuth ownership.</li>
                    <li>Execute a digitally signed Pentesting Rules of Engagement (ROE) contract.</li>
                  </ul>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>
                    Compliance complies with CFAA and Computer Misuse Act standards.
                  </span>
                </div>

                <div className="glass-panel">
                  <h4 style={{ margin: '0 0 12px 0', fontWeight: 700 }}>Recent Platform Logs</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: 8 }}>
                      <span style={{ color: 'var(--text-muted)' }}>02 min ago • </span> 
                      PR Suggestion generated for <span style={{ color: 'var(--accent-orange)' }}>geolzen-prod-auth</span>
                    </div>
                    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: 8 }}>
                      <span style={{ color: 'var(--text-muted)' }}>10 min ago • </span> 
                      Repository scan completed: found <span style={{ color: 'var(--color-critical)' }}>1 critical</span> issues.
                    </div>
                    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: 8 }}>
                      <span style={{ color: 'var(--text-muted)' }}>1 hour ago • </span> 
                      Target <span style={{ color: 'var(--text-primary)' }}>geolzen.io</span> was registered by Sandbox Corp.
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* TARGETS & VERIFICATION TAB */}
        {activeTab === 'targets' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32, flexWrap: 'wrap', gap: 16 }}>
              <div>
                <h1 style={{ fontSize: '2.2rem', margin: '0 0 8px 0', fontWeight: 800 }}>Targets Registry</h1>
                <p style={{ color: 'var(--text-secondary)', margin: 0 }}>Register new endpoints, verify domain credentials, and manage testing permissions.</p>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <div style={{ padding: '8px 16px', background: 'rgba(255, 107, 0, 0.1)', border: '1px solid var(--accent-orange)', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Current Plan</div>
                    <div style={{ fontWeight: 'bold', textTransform: 'capitalize' }}>{orgData?.plan_tier || 'Free'} ({targets.length}/{orgData?.plan_tier === 'team' ? '∞' : (orgData?.plan_tier === 'starter' ? 3 : 1)})</div>
                  </div>
                  {orgData?.plan_tier !== 'team' && (
                    <button onClick={() => { setUpgradeModalReason(null); setShowUpgradeModal(true); }} className="glow-btn" style={{ padding: '6px 12px', fontSize: '0.8rem' }}>Upgrade</button>
                  )}
                </div>
                <button onClick={() => setShowAddModal(true)} className="glow-btn" style={{ height: 'fit-content', alignSelf: 'center' }}>
                  <Plus size={16} /> Add Target Endpoint
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 20 }}>
              {targets.map(target => (
                <div key={target.id} className="glass-panel">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, flexWrap: 'wrap' }}>
                        {target.type === 'domain' ? <Globe size={22} color="var(--accent-orange)" /> : <GithubIcon size={22} color="var(--accent-orange)" />}
                        <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700 }}>{target.name}</h3>
                        <span style={{ fontSize: '0.7rem', padding: '2px 8px', borderRadius: 4, backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                          {target.type}
                        </span>
                      </div>
                      
                      <div style={{ display: 'flex', gap: 16, fontSize: '0.85rem', color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {target.verified ? <ShieldCheck size={16} color="var(--color-success)" /> : <ShieldAlert size={16} color="var(--color-high)" />}
                          Ownership: {target.verified ? `Verified (via ${target.verificationMethod.toUpperCase()})` : 'Unverified'}
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <FileText size={16} color={target.signedROE ? "var(--color-success)" : "var(--color-medium)"} />
                          Legal Consent: {target.signedROE ? `Signed (${target.signedDate})` : 'Missing Signed ROE'}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      {!target.verified && (
                        <button 
                          onClick={() => {
                            setActiveVerifyTarget(target);
                            setVerificationMethod(target.type === 'domain' ? 'dns' : 'oauth');
                          }}
                          className="glow-btn"
                          style={{ padding: '8px 16px', fontSize: '0.85rem' }}
                        >
                          Verify Ownership
                        </button>
                      )}

                      {target.verified && !target.signedROE && (
                        <button 
                          onClick={() => {
                            setLegalTarget(target);
                            setShowLegalModal(true);
                          }}
                          className="glow-btn"
                          style={{ background: 'linear-gradient(135deg, var(--color-medium), var(--color-high))', color: '#000', padding: '8px 16px', fontSize: '0.85rem' }}
                        >
                          Sign Consent Form
                        </button>
                      )}

                      {target.verified && target.signedROE && (
                        <button 
                          onClick={() => {
                            setSelectedTargetId(target.id);
                            setActiveTab('scan');
                          }}
                          className="glow-btn-outline"
                          style={{ padding: '8px 16px', fontSize: '0.85rem' }}
                        >
                          Configure Scan
                        </button>
                      )}

                      <button 
                        onClick={async () => {
                          if (supabaseClient) {
                            await supabaseClient.from('targets').delete().eq('id', target.id);
                          }
                          setTargets(targets.filter(t => t.id !== target.id));
                        }}
                        className="glow-btn-danger"
                        style={{ padding: '8px 12px', fontSize: '0.85rem' }}
                      >
                        Remove
                      </button>
                    </div>
                  </div>

                  {/* Internal Verification state details box if unverified */}
                  {!target.verified && (
                    <div style={{
                      marginTop: 20,
                      padding: 16,
                      backgroundColor: 'rgba(255, 107, 0, 0.02)',
                      border: '1px dashed rgba(255, 107, 0, 0.2)',
                      borderRadius: 8,
                      fontSize: '0.85rem'
                    }}>
                      <strong style={{ color: 'var(--accent-orange)', display: 'block', marginBottom: 8 }}>Verification Required</strong>
                      To prevent unauthorized testing (hacking), Geolzen blocks all active scans until target access is confirmed. 
                      You must add a DNS TXT record containing:
                      <code style={{
                        display: 'block',
                        margin: '8px 0',
                        padding: 10,
                        backgroundColor: '#040407',
                        border: '1px solid rgba(255,255,255,0.08)',
                        borderRadius: 4,
                        color: 'var(--color-high)',
                        fontFamily: 'var(--font-mono)'
                      }}>
                        {target.verificationToken}
                      </code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SCAN CONSOLE TAB */}
        {activeTab === 'scan' && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h1 style={{ fontSize: '2.2rem', margin: '0 0 8px 0', fontWeight: 800 }}>Scan Orchestrator</h1>
              <p style={{ color: 'var(--text-secondary)', margin: 0 }}>Configure and run automated security pipelines against verified target systems.</p>
            </div>

            <div className="grid-layout-scan">
              
              {/* Scan Configuration */}
              <div className="glass-panel">
                <h3 style={{ margin: '0 0 20px 0', fontSize: '1.2rem', fontWeight: 700 }}>Scan Configuration</h3>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>Select Target</label>
                  <select 
                    value={selectedTargetId} 
                    onChange={(e) => {
                      setSelectedTargetId(e.target.value);
                      setConsoleLogs([]);
                    }}
                    disabled={isScanning}
                    style={{
                      width: '100%',
                      padding: 12,
                      backgroundColor: '#0a0a0f',
                      border: '1px solid rgba(255, 107, 0, 0.2)',
                      borderRadius: 8,
                      color: '#fff',
                      fontSize: '0.9rem'
                    }}
                  >
                    {targets.map(t => (
                      <option key={t.id} value={t.id}>{t.name} ({t.type})</option>
                    ))}
                  </select>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>Pipeline Scanners</label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <input type="checkbox" defaultChecked disabled style={{ accentColor: 'var(--accent-orange)' }} />
                      <span>OWASP ZAP Engine (DAST / HTTP check)</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <input type="checkbox" defaultChecked disabled style={{ accentColor: 'var(--accent-orange)' }} />
                      <span>Trivy CVE Analyzer (Dependency SCA)</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <input type="checkbox" defaultChecked disabled style={{ accentColor: 'var(--accent-orange)' }} />
                      <span>Subdomain Banner Grabber (Nmap / TLS)</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <input type="checkbox" defaultChecked disabled style={{ accentColor: 'var(--accent-orange)' }} />
                      <span>Cloud Posture Audit (CIS Benchmarks)</span>
                    </div>
                  </div>
                </div>

                <div style={{ marginBottom: 24 }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>Scan Type Mode</label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <button
                      type="button"
                      onClick={() => setScanTypeSelection('passive')}
                      className={scanTypeSelection === 'passive' ? "glow-btn" : "glow-btn-outline"}
                      style={{ padding: '8px 4px', fontSize: '0.8rem' }}
                      disabled={isScanning}
                    >
                      Passive (Free)
                    </button>
                    <button
                      type="button"
                      onClick={() => setScanTypeSelection('active')}
                      className={scanTypeSelection === 'active' ? "glow-btn" : "glow-btn-outline"}
                      style={{ padding: '8px 4px', fontSize: '0.8rem' }}
                      disabled={isScanning}
                    >
                      Active Full
                    </button>
                  </div>
                </div>

                {!selectedTarget?.verified ? (
                  <div style={{ color: 'var(--color-high)', fontSize: '0.8rem', textAlign: 'center', border: '1px solid var(--color-high)', borderRadius: 6, padding: 10, background: 'rgba(255,159,67,0.05)' }}>
                    Target is not verified. Please verify ownership first.
                  </div>
                ) : !selectedTarget?.signedROE ? (
                  <div style={{ color: 'var(--color-medium)', fontSize: '0.8rem', textAlign: 'center', border: '1px solid var(--color-medium)', borderRadius: 6, padding: 10, background: 'rgba(251,197,49,0.05)' }}>
                    Legal authorization document is missing. Consent is required before scanning.
                  </div>
                ) : (
                  <button 
                    onClick={startScan}
                    disabled={isScanning}
                    className="glow-btn"
                    style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
                  >
                    <Terminal size={18} /> {isScanning ? 'Scan Running...' : 'Execute Security Scan'}
                  </button>
                )}
              </div>

              {/* Interactive Terminal console output logs */}
              <div>
                <div className="terminal-window">
                  <div className="terminal-header">
                    <div className="terminal-dots">
                      <div className="terminal-dot red"></div>
                      <div className="terminal-dot yellow"></div>
                      <div className="terminal-dot green"></div>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>geolzen-scanner-daemon.log</span>
                    <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: 4, backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                      {selectedTarget ? selectedTarget.name : 'daemon idle'}
                    </span>
                  </div>

                  <div className="terminal-body">
                    {consoleLogs.length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: 100 }}>
                        <Terminal size={40} style={{ opacity: 0.15, marginBottom: 12 }} />
                        <p>Configure a target and click "Execute Security Scan" to view live telemetry.</p>
                      </div>
                    ) : (
                      consoleLogs.map((log, index) => {
                        let color = 'inherit';
                        if (log.includes('[CRITICAL]')) color = 'var(--color-critical)';
                        else if (log.includes('[HIGH]')) color = 'var(--color-high)';
                        else if (log.includes('[WARNING]')) color = 'var(--color-medium)';
                        else if (log.includes('[RECON]')) color = 'var(--accent-orange-bright)';
                        else if (log.includes('SUCCESSFULLY')) color = 'var(--color-success)';

                        return (
                          <div key={index} style={{ color, marginBottom: 6 }}>
                            {log}
                          </div>
                        );
                      })
                    )}
                    <div ref={consoleEndRef} />
                  </div>
                </div>

                {isScanning && (
                  <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    <RefreshCw size={14} className="animate-spin" color="var(--accent-orange)" />
                    <span>Analyzing targets. Container execution remains fully isolated.</span>
                  </div>
                )}
              </div>

            </div>
          </div>
        )}

        {/* FINDINGS & AUTO-REMEDIATION TAB */}
        {activeTab === 'findings' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32, flexWrap: 'wrap', gap: 16 }}>
              <div>
                <h1 style={{ fontSize: '2.2rem', margin: '0 0 8px 0', fontWeight: 800 }}>Vulnerabilities & Auto-Remediation</h1>
                <p style={{ color: 'var(--text-secondary)', margin: 0 }}>Review vulnerabilities and apply automated, developer-approved pull requests or configuration patches.</p>
              </div>

              {selectedTarget?.vulnerabilities.length > 0 && (
                <button 
                  onClick={downloadPDFReport}
                  className="glow-btn-outline"
                >
                  <Download size={16} /> Export Audit Report
                </button>
              )}
            </div>

            {/* Split layout: left list, right detail */}
            {selectedTarget?.vulnerabilities.length === 0 ? (
              <div className="glass-panel" style={{ padding: 60, textAlign: 'center', color: 'var(--text-secondary)' }}>
                <CheckCircle size={48} color="var(--color-success)" style={{ marginBottom: 16 }} />
                <h3>No Vulnerabilities Found</h3>
                <p>Ensure you have verified the target ownership, signed the consent agreement, and run a full active scan.</p>
              </div>
            ) : (
              <div className="grid-layout-findings">
                
                {/* Vuln List */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  
                  {/* Severity Filters */}
                  <div className="glass-panel" style={{ padding: 12, display: 'flex', justifyContent: 'space-around', gap: 4 }}>
                    <button
                      type="button"
                      onClick={() => setVulnFilter('all')}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: vulnFilter === 'all' ? 'var(--accent-orange)' : 'var(--text-secondary)',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      All
                    </button>
                    <button
                      type="button"
                      onClick={() => setVulnFilter('critical')}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: vulnFilter === 'critical' ? 'var(--color-critical)' : 'var(--text-secondary)',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Critical
                    </button>
                    <button
                      type="button"
                      onClick={() => setVulnFilter('high')}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: vulnFilter === 'high' ? 'var(--color-high)' : 'var(--text-secondary)',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      High
                    </button>
                    <button
                      type="button"
                      onClick={() => setVulnFilter('medium')}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: vulnFilter === 'medium' ? 'var(--color-medium)' : 'var(--text-secondary)',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Medium
                    </button>
                  </div>

                  {/* List cards */}
                  {selectedTarget?.vulnerabilities
                    .filter(v => vulnFilter === 'all' || v.severity === vulnFilter)
                    .map(v => (
                      <div 
                        key={v.id}
                        onClick={() => setSelectedVulnId(v.id)}
                        style={{
                          padding: 16,
                          backgroundColor: selectedVulnId === v.id ? 'rgba(255, 107, 0, 0.08)' : 'rgba(16, 17, 24, 0.4)',
                          border: selectedVulnId === v.id ? '1px solid var(--accent-orange)' : '1px solid rgba(255,255,255,0.05)',
                          borderRadius: 8,
                          cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                          <span className={`badge badge-${v.severity}`}>{v.severity}</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{v.category}</span>
                        </div>
                        <h4 style={{ margin: '0 0 6px 0', fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>{v.title}</h4>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>File: {v.fileName}</span>
                          {v.remediated && (
                            <span style={{ fontSize: '0.75rem', color: 'var(--color-success)', display: 'flex', alignItems: 'center', gap: 4 }}>
                              <Check size={12} /> Remediated
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                </div>

                {/* Details view */}
                {selectedVuln ? (
                  <div className="glass-panel">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: 20, marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                          <span className={`badge badge-${selectedVuln.severity}`}>{selectedVuln.severity}</span>
                          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{selectedVuln.category}</span>
                        </div>
                        <h3 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700 }}>{selectedVuln.title}</h3>
                      </div>

                      {!selectedVuln.remediated ? (
                        <button 
                          onClick={() => applyRemediation(selectedVuln.id)}
                          className="glow-btn"
                          style={{
                            background: 'linear-gradient(135deg, var(--color-success), var(--accent-orange))',
                            color: '#060609'
                          }}
                        >
                          <GitPullRequest size={16} /> 
                          {selectedVuln.remediationType === 'pr' ? 'Generate Pull Request' : 'Apply Security Patch'}
                        </button>
                      ) : (
                        <button 
                          disabled
                          className="glow-btn-success"
                          style={{ opacity: 0.8 }}
                        >
                          <Check size={16} /> Applied / Remediated
                        </button>
                      )}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, marginBottom: 28 }}>
                      <div>
                        <strong style={{ color: 'var(--text-primary)', display: 'block', fontSize: '0.9rem', marginBottom: 6 }}>Plain-English Explanation</strong>
                        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selectedVuln.description}</p>
                      </div>

                      <div>
                        <strong style={{ color: 'var(--text-primary)', display: 'block', fontSize: '0.9rem', marginBottom: 6 }}>Security Impact</strong>
                        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selectedVuln.impact}</p>
                      </div>

                      <div>
                        <strong style={{ color: 'var(--text-primary)', display: 'block', fontSize: '0.9rem', marginBottom: 6 }}>Proposed Resolution</strong>
                        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selectedVuln.solution}</p>
                      </div>
                    </div>

                    {/* Interactive side-by-side diff code block */}
                    <div style={{ marginBottom: 28 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '0.9rem' }}>Remediation Patch View</strong>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                          <FileCode size={14} /> {selectedVuln.fileName}
                        </span>
                      </div>
                      {renderCodeDiff(selectedVuln.originalCode, selectedVuln.fixedCode)}
                    </div>

                    {/* Security Analyst Support Chat Container */}
                    <div className="analyst-chat-panel">
                      <div className="analyst-chat-header">
                        <MessageSquare size={16} color="var(--accent-orange)" />
                        <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Security Analyst Copilot</span>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: 'var(--color-success)', marginLeft: 'auto' }}></div>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Online</span>
                      </div>

                      <div className="analyst-chat-body">
                        {selectedVuln.chatHistory.map((chat, idx) => (
                          <div key={idx} className={`chat-bubble ${chat.sender === 'user' ? 'chat-bubble-user' : 'chat-bubble-analyst'}`}>
                            {chat.text}
                          </div>
                        ))}
                      </div>

                      <form onSubmit={handleChatMessageSubmit} className="chat-input-area">
                        <input 
                          type="text" 
                          placeholder="Ask details (e.g. 'Is this a false positive?' or 'How do I test this?')"
                          value={chatMessageInput}
                          onChange={(e) => setChatMessageInput(e.target.value)}
                        />
                        <button type="submit">
                          <Send size={16} />
                        </button>
                      </form>
                    </div>

                  </div>
                ) : (
                  <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)' }}>
                    Select a vulnerability finding from the list to view remediations.
                  </div>
                )}

              </div>
            )}
          </div>
        )}

        {/* SETTINGS TAB */}
        {activeTab === 'settings' && (
          <div>
            <div style={{ marginBottom: 32 }}>
              <h1 style={{ fontSize: '2.2rem', margin: '0 0 8px 0', fontWeight: 800 }}>Platform Settings</h1>
              <p style={{ color: 'var(--text-secondary)', margin: 0 }}>Personalize your console experience, configure alerts, and manage Supabase database credentials.</p>
            </div>

            <div className="grid-layout-settings">
              
              {/* Settings navigation sidebar */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button
                  type="button"
                  onClick={() => setSettingsView('profile')}
                  className={`glow-btn-outline ${settingsView === 'profile' ? 'active' : ''}`}
                  style={{
                    justifyContent: 'flex-start',
                    border: settingsView === 'profile' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                    background: settingsView === 'profile' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                    color: settingsView === 'profile' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                  }}
                >
                  <User size={16} /> Profile Details
                </button>
                <button
                  type="button"
                  onClick={() => setSettingsView('alerts')}
                  className={`glow-btn-outline ${settingsView === 'alerts' ? 'active' : ''}`}
                  style={{
                    justifyContent: 'flex-start',
                    border: settingsView === 'alerts' ? '1px solid var(--accent-orange)' : '1px solid transparent',
                    background: settingsView === 'alerts' ? 'rgba(255, 107, 0, 0.1)' : 'transparent',
                    color: settingsView === 'alerts' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                  }}
                >
                  <Sliders size={16} /> Alert Rules
                </button>
              </div>

              {/* Settings details pane */}
              <div className="glass-panel">
                
                {/* PROFILE VIEW */}
                {settingsView === 'profile' && (
                  <form onSubmit={handleProfileUpdate}>
                    <h3 style={{ margin: '0 0 20px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: 10 }}>Personalize Profile</h3>
                    
                    <div className="form-group" style={{ marginBottom: 20 }}>
                      <label>Full Name</label>
                      <input 
                        type="text" 
                        value={editFullName}
                        onChange={(e) => setEditFullName(e.target.value)}
                        style={{ width: '100%', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', backgroundColor: '#040407', color: '#fff' }}
                      />
                    </div>

                    <div className="form-group" style={{ marginBottom: 24 }}>
                      <label>Organization Workspace Name</label>
                      <input 
                        type="text" 
                        value={editOrgName}
                        onChange={(e) => setEditOrgName(e.target.value)}
                        style={{ width: '100%', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', backgroundColor: '#040407', color: '#fff' }}
                      />
                    </div>

                    <button type="submit" className="glow-btn" style={{ padding: '10px 24px' }}>
                      Save Changes
                    </button>
                  </form>
                )}

                {/* ALERTS VIEW */}
                {settingsView === 'alerts' && (
                  <div>
                    <h3 style={{ margin: '0 0 20px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: 10 }}>Security Alert Rules</h3>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 28 }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                        <input 
                          type="checkbox" 
                          id="email-alert-check"
                          checked={enableEmailAlerts}
                          onChange={(e) => setEnableEmailAlerts(e.target.checked)}
                          style={{ marginTop: 4, accentColor: 'var(--accent-orange)' }}
                        />
                        <div>
                          <label htmlFor="email-alert-check" style={{ fontWeight: 600, color: 'var(--text-primary)', cursor: 'pointer' }}>Email Notifications</label>
                          <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Receive detailed PDF audit files on weekly scans to {userProfile.email}.</span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                        <input 
                          type="checkbox" 
                          id="slack-alert-check"
                          checked={enableSlackAlerts}
                          onChange={(e) => setEnableSlackAlerts(e.target.checked)}
                          style={{ marginTop: 4, accentColor: 'var(--accent-orange)' }}
                        />
                        <div>
                          <label htmlFor="slack-alert-check" style={{ fontWeight: 600, color: 'var(--text-primary)', cursor: 'pointer' }}>Slack Webhook Alerts</label>
                          <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 8 }}>Ping Slack channels upon finding critical security vulnerabilities.</span>
                          {enableSlackAlerts && (
                            <input 
                              type="text" 
                              value={slackWebhookUrl}
                              onChange={(e) => setSlackWebhookUrl(e.target.value)}
                              style={{ width: '100%', padding: 10, borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', backgroundColor: '#040407', color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}
                            />
                          )}
                        </div>
                      </div>
                    </div>

                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 20 }}>
                      <h4 style={{ margin: '0 0 12px 0', fontSize: '0.95rem' }}>Scan Intensity Policy</h4>
                      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.85rem' }}>
                          <input type="radio" name="intensity" checked={scanIntensity === 'safe'} onChange={() => setScanIntensity('safe')} style={{ accentColor: 'var(--accent-orange)' }} />
                          <span>Safe Mode (Non-destructive, rate-limited)</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.85rem' }}>
                          <input type="radio" name="intensity" checked={scanIntensity === 'aggressive'} onChange={() => setScanIntensity('aggressive')} style={{ accentColor: 'var(--accent-orange)' }} />
                          <span style={{ color: 'var(--color-high)' }}>Aggressive Mode (Exploit payloads check)</span>
                        </label>
                      </div>
                    </div>
                  </div>
                )}



              </div>

            </div>
          </div>
        )}

      </main>

      {/* Target Add Modal */}
      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)',
          display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '450px', position: 'relative' }}>
            <h3 style={{ margin: '0 0 8px 0', fontSize: '1.4rem', fontWeight: 800 }}>Register Target Scope</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 24px 0' }}>Configure a scope domain or codebase repository to perform audits.</p>
            
            <form onSubmit={handleAddTarget}>
              <div style={{ marginBottom: 18 }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>Target Category</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <button
                    type="button"
                    onClick={() => setNewTargetType('domain')}
                    className={newTargetType === 'domain' ? "glow-btn" : "glow-btn-outline"}
                    style={{ padding: '10px 4px', fontSize: '0.85rem', justifyContent: 'center' }}
                  >
                    Domain / URL
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewTargetType('repository')}
                    className={newTargetType === 'repository' ? "glow-btn" : "glow-btn-outline"}
                    style={{ padding: '10px 4px', fontSize: '0.85rem', justifyContent: 'center' }}
                  >
                    Git Repository
                  </button>
                </div>
              </div>

              <div style={{ marginBottom: 24 }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                  {newTargetType === 'domain' ? 'Domain Address' : 'GitHub Repository Path'}
                </label>
                <input
                  type="text"
                  placeholder={newTargetType === 'domain' ? 'company.com' : 'org/repo-name'}
                  value={newTargetName}
                  onChange={(e) => setNewTargetName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: 12,
                    backgroundColor: '#0a0a0f',
                    border: '1px solid rgba(255, 107, 0, 0.2)',
                    borderRadius: 8,
                    color: '#fff',
                    outline: 'none',
                    fontSize: '0.9rem'
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="glow-btn-outline"
                  style={{ padding: '10px 20px', fontSize: '0.85rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="glow-btn"
                  style={{ padding: '10px 20px', fontSize: '0.85rem' }}
                >
                  Register
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Verification Wizard Overlay */}
      {activeVerifyTarget && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)',
          display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '500px' }}>
            <h3 style={{ margin: '0 0 8px 0', fontSize: '1.4rem', fontWeight: 800 }}>Confirm Target Ownership</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 24px 0' }}>
              Proof of ownership is legally required. Choose a method below to verify you control <strong style={{ color: 'var(--text-primary)' }}>{activeVerifyTarget.name}</strong>.
            </p>

            <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
              {activeVerifyTarget.type === 'domain' ? (
                <>
                  <button 
                    onClick={() => { setVerificationMethod('dns'); setRealDnsVerifyResponse(null); }}
                    className={verificationMethod === 'dns' ? "glow-btn" : "glow-btn-outline"}
                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                  >
                    DNS TXT Record
                  </button>
                  <button 
                    onClick={() => { setVerificationMethod('file'); setRealDnsVerifyResponse(null); }}
                    className={verificationMethod === 'file' ? "glow-btn" : "glow-btn-outline"}
                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                  >
                    Meta file upload
                  </button>
                </>
              ) : (
                <button 
                  onClick={() => { setVerificationMethod('oauth'); setRealDnsVerifyResponse(null); }}
                  className={verificationMethod === 'oauth' ? "glow-btn" : "glow-btn-outline"}
                  style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                >
                  OAuth Verification
                </button>
              )}
            </div>

            {verificationMethod === 'dns' && (
              <div style={{ marginBottom: 20, fontSize: '0.85rem' }}>
                <p style={{ margin: '0 0 10px 0', color: 'var(--text-secondary)' }}>
                  Add the following TXT record to your DNS nameserver settings: 
                  <span onClick={() => setShowHowToModal(true)} style={{ color: 'var(--accent-orange)', cursor: 'pointer', marginLeft: 8, textDecoration: 'underline' }}>How to do it?</span>
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, backgroundColor: '#040407', border: '1px solid rgba(255, 107, 0, 0.15)', padding: 12, borderRadius: 6, fontFamily: 'var(--font-mono)' }}>
                  <div>Type: <span style={{ color: 'var(--accent-orange)' }}>TXT</span></div>
                  <div>Name: <span style={{ color: 'var(--accent-orange)' }}>@</span></div>
                  <div>TXT Value: <span style={{ color: 'var(--color-high)' }}>{activeVerifyTarget.verificationToken}</span></div>
                </div>
              </div>
            )}

            {verificationMethod === 'file' && (
              <div style={{ marginBottom: 20, fontSize: '0.85rem' }}>
                <p style={{ margin: '0 0 10px 0', color: 'var(--text-secondary)' }}>
                  Upload a plain text verification file to your web server host root:
                  <span onClick={() => setShowHowToModal(true)} style={{ color: 'var(--accent-orange)', cursor: 'pointer', marginLeft: 8, textDecoration: 'underline' }}>How to do it?</span>
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, backgroundColor: '#040407', border: '1px solid rgba(255, 107, 0, 0.15)', padding: 12, borderRadius: 6, fontFamily: 'var(--font-mono)' }}>
                  <div>URL Endpoint: <span style={{ color: 'var(--accent-orange)' }}>https://{activeVerifyTarget.name}/.well-known/securescan-verify.txt</span></div>
                  <div>Content: <span style={{ color: 'var(--color-high)' }}>{activeVerifyTarget.verificationToken}</span></div>
                </div>
              </div>
            )}

            {verificationMethod === 'oauth' && (
              <div style={{ marginBottom: 20, fontSize: '0.85rem' }}>
                <p style={{ margin: '0 0 16px 0', color: 'var(--text-secondary)' }}>Authenticate using scoped OAuth tokens to prove write access:</p>
                <div style={{ display: 'flex', justifyContent: 'center', padding: '12px', border: '1px dashed rgba(255, 107, 0, 0.2)', borderRadius: 8 }}>
                  <button
                    type="button"
                    onClick={() => {
                      if (activeVerifyTarget) {
                        window.location.href = `${BACKEND_URL}/api/auth/github?targetId=${activeVerifyTarget.id}`;
                      }
                    }}
                    className="glow-btn"
                    style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', fontSize: '0.9rem' }}
                  >
                    <GithubIcon size={18} /> Connect via Authorized GitHub Account
                  </button>
                </div>
              </div>
            )}

            {/* Strict verification feedback (simulation bypass removed for legal safety compliance) */}
            {realDnsVerifyResponse && !realDnsVerifyResponse.success && (
              <div style={{
                marginBottom: 20,
                padding: 12,
                borderRadius: 6,
                border: '1px solid rgba(255, 60, 60, 0.3)',
                backgroundColor: 'rgba(255, 60, 60, 0.05)',
                fontSize: '0.8rem',
                color: 'var(--color-critical)'
              }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>Nameserver Verification Failed</div>
                <div style={{ marginBottom: 6 }}>{realDnsVerifyResponse.message}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Records read: {realDnsVerifyResponse.recordsFound}</div>
                <div style={{ marginTop: 10, fontSize: '0.75rem', color: 'var(--color-critical)', borderTop: '1px solid rgba(255,60,60,0.2)', paddingTop: 8 }}>
                  ⚠️ Legally compliant operations require verified ownership. Active pentesting scans cannot be bypassed.
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button 
                onClick={() => { setActiveVerifyTarget(null); setRealDnsVerifyResponse(null); }}
                className="glow-btn-outline"
                disabled={isVerifying}
              >
                Cancel
              </button>
              <button 
                onClick={performActualVerification}
                className="glow-btn"
                disabled={isVerifying}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}
              >
                {isVerifying ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" /> Querying DNS...
                  </>
                ) : (
                  'Perform Check'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rules of Engagement Legal Agreement Modal */}
      {showHowToModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)',
          display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1100
        }}>
          <div className="glass-panel" style={{ width: '600px', maxHeight: '90vh', overflowY: 'auto' }}>
            <h3 style={{ margin: '0 0 15px 0', fontSize: '1.2rem', fontWeight: 700 }}>Verification Guide</h3>
            
            {verificationMethod === 'dns' ? (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                <p>To verify ownership using a DNS TXT record, you must add the provided token to your domain's DNS settings.</p>
                
                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>Cloudflare</h4>
                <ol style={{ paddingLeft: 20, marginTop: 0 }}>
                  <li>Log in and select your domain.</li>
                  <li>Go to <strong>DNS</strong> {'>'} <strong>Records</strong>.</li>
                  <li>Click <strong>Add Record</strong>.</li>
                  <li>Set Type to <strong>TXT</strong>, Name to <strong>@</strong>, and Content to your token.</li>
                  <li>Click <strong>Save</strong>.</li>
                </ol>

                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>Namecheap</h4>
                <ol style={{ paddingLeft: 20, marginTop: 0 }}>
                  <li>Log in, go to <strong>Domain List</strong>, and click <strong>Manage</strong> next to your domain.</li>
                  <li>Go to the <strong>Advanced DNS</strong> tab.</li>
                  <li>Click <strong>Add New Record</strong>.</li>
                  <li>Set Type to <strong>TXT Record</strong>, Host to <strong>@</strong>, and Value to your token.</li>
                  <li>Click the checkmark to save.</li>
                </ol>

                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>GoDaddy</h4>
                <ol style={{ paddingLeft: 20, marginTop: 0 }}>
                  <li>Log in, go to <strong>My Products</strong>, and click <strong>DNS</strong> next to your domain.</li>
                  <li>Scroll to the <strong>Records</strong> section and click <strong>Add</strong>.</li>
                  <li>Set Type to <strong>TXT</strong>, Name to <strong>@</strong>, and Value to your token.</li>
                  <li>Click <strong>Save</strong>.</li>
                </ol>
                <p style={{ marginTop: 15, color: 'var(--color-medium)' }}>
                  <em>Note: DNS changes can take a few minutes to propagate globally. You can verify it propagated using tools like dnschecker.org before clicking "Perform Check".</em>
                </p>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                <p>To verify ownership using a Meta File, you must serve a plain text file at a specific URL on your web server.</p>
                
                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>SSH / VPS Upload</h4>
                <pre style={{ backgroundColor: 'rgba(0,0,0,0.5)', padding: 10, borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', overflowX: 'auto', marginTop: 5 }}>
mkdir -p /var/www/html/.well-known
echo "{activeVerifyTarget?.verificationToken}" {'>'} /var/www/html/.well-known/securescan-verify.txt
                </pre>

                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>Nginx Configuration</h4>
                <p style={{ marginBottom: 5 }}>Ensure your `.well-known` directory is permitted to be served:</p>
                <pre style={{ backgroundColor: 'rgba(0,0,0,0.5)', padding: 10, borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', overflowX: 'auto', marginTop: 0 }}>
location /.well-known/ {'{'}
    allow all;
{'}'}
                </pre>

                <h4 style={{ color: '#fff', marginTop: 15, marginBottom: 5 }}>Vercel / Netlify / Static Hosts</h4>
                <p style={{ marginTop: 0 }}>
                  Create the file at <code>public/.well-known/securescan-verify.txt</code> within your project directory and redeploy your application.
                </p>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 25 }}>
              <button 
                className="glow-btn" 
                onClick={() => setShowHowToModal(false)}
                style={{ padding: '8px 20px' }}
              >
                Got it
              </button>
            </div>
          </div>
        </div>
      )}

      {showLegalModal && legalTarget && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)',
          display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '600px', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '1.4rem', fontWeight: 800 }}>Rules of Engagement (ROE)</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 20px 0' }}>
              Legal consent authorization agreement for active vulnerability scanning.
            </p>

            <div style={{
              flex: 1, overflowY: 'auto', padding: 16, backgroundColor: '#040407', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 8, fontSize: '0.8rem', lineHeight: 1.6, color: 'var(--text-secondary)', marginBottom: 20
            }}>
              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 10px 0' }}>1. Scope of Testing</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                This authorization permits Geolzen to conduct automated vulnerability scanning, network mapping, and software dependency audits against the registered target:
                <strong style={{ color: 'var(--accent-orange)', display: 'block', margin: '4px 0' }}>{legalTarget.name} ({legalTarget.type.toUpperCase()})</strong>
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 10px 0' }}>2. Authorization & Consent</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                The signatory represents and warrants that they possess full legal authority, rights, and corporate authorization to permit vulnerability assessments on the systems, assets, and networks comprising the targets listed above.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 10px 0' }}>3. Destructive Testing Restrictions</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                All automated tests must default to non-destructive configurations. No denial-of-service, buffer overflow exploitation, brute-forcing, or data-wiping payloads are authorized. Test rate limits will match standard parameters to avoid production disruption.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 10px 0' }}>4. Disclaimer of Warranty & Liabilities</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                Vulnerability assessments are performed "as-is". Geolzen does not represent that scanning identifies all possible threats or bugs. The signatory indemnifies Geolzen against system hiccups arising from default scanning methods.
              </p>
            </div>

            <form onSubmit={handleSignROE}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 6 }}>Full Legal Name</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="Jane Doe"
                    value={roeName}
                    onChange={(e) => setRoeName(e.target.value)}
                    style={{
                      width: '100%', padding: 10, backgroundColor: '#0a0a0f', border: '1px solid rgba(255, 107, 0, 0.2)', borderRadius: 6, color: '#fff', fontSize: '0.85rem'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 6 }}>Company Name</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="Sandbox Corp"
                    value={roeCompany}
                    onChange={(e) => setRoeCompany(e.target.value)}
                    style={{
                      width: '100%', padding: 10, backgroundColor: '#0a0a0f', border: '1px solid rgba(255, 107, 0, 0.2)', borderRadius: 6, color: '#fff', fontSize: '0.85rem'
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 24 }}>
                <input 
                  type="checkbox" 
                  id="roe-check"
                  required
                  checked={roeAccept}
                  onChange={(e) => setRoeAccept(e.target.checked)}
                  style={{ marginTop: 3, accentColor: 'var(--accent-orange)' }} 
                />
                <label htmlFor="roe-check" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer', userSelect: 'none' }}>
                  I declare under penalty of perjury that I hold admin rights to target {legalTarget.name} and accept these Rules of Engagement.
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                <button 
                  type="button" 
                  className="glow-btn-outline"
                  onClick={() => {
                    setShowLegalModal(false);
                    setLegalTarget(null);
                  }}
                >
                  Reject
                </button>
                <button 
                  type="submit" 
                  className="glow-btn"
                  style={{ background: 'linear-gradient(135deg, var(--color-success), var(--accent-orange))', color: '#060609' }}
                >
                  Accept & Sign ROE
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer style={{
        marginTop: 'auto',
        borderTop: '1px solid rgba(255,255,255,0.03)',
        padding: '24px 0',
        backgroundColor: '#030305',
        fontSize: '0.8rem',
        color: 'var(--text-muted)',
        textAlign: 'center'
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <span>© 2026 Geolzen Inc. All rights reserved.</span>
          <div style={{ display: 'flex', gap: 20 }}>
            <button 
              onClick={() => setShowPrivacyModal(true)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', textDecoration: 'underline', padding: 0 }}
            >
              Privacy Policy
            </button>
            <a href="#" style={{ color: 'var(--text-muted)' }}>Rules of Engagement</a>
            <a href="#" style={{ color: 'var(--text-muted)' }}>SLA</a>
          </div>
        </div>
      </footer>

      {/* Global Privacy Modal for Authenticated Session */}
      {showPrivacyModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)',
          display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 2000
        }}>
          <div className="glass-panel" style={{ width: '550px', maxHeight: '80vh', display: 'flex', flexDirection: 'column', padding: 28 }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '1.3rem', fontWeight: 800 }}>Geolzen Privacy Policy</h3>
            
            <div style={{
              flex: 1, overflowY: 'auto', padding: 16, backgroundColor: '#040407', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 8, fontSize: '0.8rem', lineHeight: 1.6, color: 'var(--text-secondary)', marginBottom: 20
            }}>
              <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>1. Data Collection Scopes</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                Geolzen collects target domain URLs, DNS configurations, dependency library structures, and compliance logs (names, company titles, signature timestamps, and source IP addresses).
              </p>
              <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>2. Data Utilization Rules</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                Data is processed exclusively to run security audits, compile side-by-side git diff configurations, execute auto-remediations, and tune the analyst support copilot responses.
              </p>
              <h4 style={{ color: '#fff', margin: '0 0 8px 0' }}>3. Supabase Storage & Security</h4>
              <p style={{ margin: '0 0 12px 0' }}>
                Operations details are stored in Supabase PostgreSQL databases with Row-Level Security (RLS). Users can only access metrics linked to their verified organization workspace.
              </p>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button 
                onClick={() => setShowPrivacyModal(false)}
                className="glow-btn"
              >
                Close Policy
              </button>
            </div>
          </div>
        </div>
      )}

      {/* UPGRADE MODAL */}
      {showUpgradeModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 2000,
          padding: 20
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: 800, padding: 32, position: 'relative' }}>
            <button 
              onClick={() => setShowUpgradeModal(false)}
              style={{ position: 'absolute', top: 20, right: 20, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
            >
              <X size={24} />
            </button>
            <h2 style={{ margin: '0 0 8px 0', fontSize: '1.8rem', color: upgradeModalReason === 'limit_reached' ? 'var(--color-critical)' : 'var(--text-primary)' }}>
              {upgradeModalReason === 'limit_reached' ? 'Target Limit Reached' : 'Upgrade Your Plan'}
            </h2>
            <p style={{ color: 'var(--text-secondary)', margin: '0 0 24px 0' }}>
              {upgradeModalReason === 'limit_reached' 
                ? `You have hit the maximum number of targets allowed on your current tier. Please upgrade to continue expanding your attack surface coverage.`
                : `Unlock more targets and advanced autonomous security capabilities.`
              }
            </p>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24 }}>
              <div className="glass-panel" style={{ padding: 24, display: 'flex', flexDirection: 'column', border: '1px solid var(--accent-orange)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ margin: 0, color: 'var(--accent-orange)' }}>Starter</h4>
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, margin: '12px 0' }}>$49<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/mo</span></div>
                <ul style={{ paddingLeft: 18, fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8, flex: 1, margin: '0 0 20px 0' }}>
                  <li>3 Targets (Domains/Repos)</li>
                  <li>Weekly active DAST scans</li>
                  <li>Dependency SCA audits</li>
                </ul>
                <button onClick={() => { setShowUpgradeModal(false); handleCheckout('starter', 49); }} className="glow-btn" style={{ width: '100%' }}>Upgrade to Starter</button>
              </div>

              <div className="glass-panel" style={{ padding: 24, display: 'flex', flexDirection: 'column' }}>
                <h4 style={{ margin: 0, color: 'var(--text-secondary)' }}>Team</h4>
                <div style={{ fontSize: '2rem', fontWeight: 800, margin: '12px 0' }}>$299<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/mo</span></div>
                <ul style={{ paddingLeft: 18, fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8, flex: 1, margin: '0 0 20px 0' }}>
                  <li>Unlimited targets</li>
                  <li>Continuous monitoring scans</li>
                  <li>Auto-Fix pull request creation</li>
                </ul>
                <button onClick={() => { setShowUpgradeModal(false); handleCheckout('team', 299); }} className="glow-btn-outline" style={{ width: '100%' }}>Upgrade to Team</button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
