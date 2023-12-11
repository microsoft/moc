package network

func (m *NetworkInterface) GetPrimaryIpConfiguration() *IpConfiguration {
	if m != nil {
		for _, ipConfig := range m.IpConfigurations {
			if ipConfig.Primary {
				return ipConfig
			}
		}
	}
	return nil
}
