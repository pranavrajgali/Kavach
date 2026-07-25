import { DetonationProvider } from '@/context/DetonationContext';
import { EfferdDashboard2 } from '@/components/ui/efferd-dashboard-2';

function App() {
  return (
    <DetonationProvider>
      <EfferdDashboard2 />
    </DetonationProvider>
  );
}

export default App;
