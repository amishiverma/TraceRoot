export interface DependencyNode {
  id: string;
  name: string;
  version: string;
  riskScore: number; // 0-100
  category: 'direct' | 'transitive' | 'peer';
  license: string;
  downloads: string;
  maintainer: string;
  maintainerRisk: 'low' | 'medium' | 'high' | 'critical';
  cves: string[];
  threatSummary?: string;
  aiExplanation?: string;
  x?: number;
  y?: number;
  status: 'safe' | 'warning' | 'critical';
  polygonHash?: string;
}

export interface DependencyEdge {
  source: string;
  target: string;
  relationship: 'depends' | 'imports' | 'bundles' | 'transitive';
}

export interface ActivityLog {
  id: string;
  repo: string;
  branch: string;
  timestamp: string;
  riskScore: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  actionStatus: 'BLOCKED PR' | 'AUDIT PASSED' | 'FLAGGED SUSPICIOUS' | 'ANCHORED';
  details: string;
  author: string;
  commitHash: string;
  txHash: string;
}

export interface BlockchainProof {
  id: string;
  txHash: string;
  blockNumber: number;
  network: 'Polygon Mainnet' | 'Sepolia Testnet';
  timestamp: string;
  merkleRoot: string;
  repoScanDigest: string;
  gasUsed: string;
  status: 'Confirmed' | 'Minted';
  validator: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  timestamp: string;
  severity: 'critical' | 'warning' | 'info';
  read: boolean;
}

export type ActiveTab = 'overview' | 'graph' | 'analytics' | 'vulnerabilities' | 'blockchain' | 'settings';
