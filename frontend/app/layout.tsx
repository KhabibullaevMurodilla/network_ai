import "./globals.css";

export const metadata = {
  title: "Network AI — Anomaly Detection",
  description: "AI-driven anomaly detection for private 4G/5G and OT networks",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
