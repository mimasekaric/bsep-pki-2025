import { Component, OnInit } from '@angular/core';
import { TokenService } from 'src/app/services/token.service';
import { AuthService } from 'src/app/services/auth.service';
import { UAParser } from 'ua-parser-js'; 
import { HttpClient } from '@angular/common/http';

interface TokenSession {
  token: string;
  device: string;
  ipAddress: string;
  lastActive: Date; 
  current: boolean;
}

interface DisplaySession {
  token: string;
  email: string;
  fullUserAgent: string;
  ipAddress: string;
  lastActive: Date;
  current: boolean;
  browser: string;
  os: string;
  deviceType: string; 
  displayLocation: string; 
  displayDevice: string; 
}

@Component({
  selector: 'app-tokens',
  templateUrl: './tokens.component.html',
  styleUrls: ['./tokens.component.css']
})
export class TokensComponent implements OnInit {
  displaySessions: DisplaySession[] = [];
  email: string = '';

  constructor(private tokenService: TokenService, private authService: AuthService, private http: HttpClient) {}

  ngOnInit(): void {
    const currentUser = this.authService.getCurrentUser();
    if (currentUser) {
      this.email = currentUser.email;
      console.log(`User found with EMAIL: ${this.email}`);
      this.loadTokens();
    } else {
      console.error('User not logged in.');
    }
  }
/*
  loadTokens() {
    console.log(`trying token for ${this.email}`);
    if (!this.email) return;

    this.tokenService.getUserTokens(this.email).subscribe({
      next: (data: TokenSession[]) => {
        this.displaySessions = data.map(token => this.mapToDisplaySession(token));
      },
      error: (err) => {
        console.error('Error fetching tokens:', err);
      }
    });
  }
*/

async loadTokens() {
      console.log(`trying tokens for ${this.email}`);
    this.tokenService.getUserTokens(this.email).subscribe({
        next: async (data: TokenSession[]) => {
            this.displaySessions = await Promise.all(data.map(token => this.mapToDisplaySession(token)));
        },
        error: (err) => {
            console.error('Error fetching tokens:', err);
        }
    });
}

private async mapToDisplaySession(token: TokenSession): Promise<DisplaySession>  {
let curr = token.current;
  if (localStorage.getItem('jwt_token') == token.token){
      curr=true;
  }else{
    curr= false;
  }
  let location = 'Nepoznata lokacija location';
  if (token.ipAddress === '0:0:0:0:0:0:0:1' || token.ipAddress === '127.0.0.1') {
    console.log('Detected Localhost IP....');
    try {
      console.log(`User found with location: ${token.lastActive}`);
        const publicIpResponse = await this.http.get('https://api.ipify.org', { responseType: 'text' }).toPromise();
        
        if (publicIpResponse && publicIpResponse.trim()) {
            const clientPublicIp = publicIpResponse.trim();
            console.log('Fetched client public IP:', clientPublicIp);
  
            const geoData: any = await this.http.get(`https://ipapi.co/${clientPublicIp}/json/`).toPromise();
            if (geoData && geoData.status !== 'fail' && geoData.city && geoData.country_name) {
                location = `${geoData.city}, ${geoData.country_name}`;
            } else {
                location = clientPublicIp;
            }
        } else {
            location = 'Public IP nepoznat'; 
        }
    } catch (error) {
        console.error('Error fetching public IP for localhost:', error);
        location = 'Public IP nepoznat'; 
    }
}else 
  if (token.ipAddress) { 
    try {
      const geoData: any = await this.http.get(`https://ipapi.co/${token.ipAddress}/json/`).toPromise();
      if (geoData && geoData.city && geoData.country_name) {
        location = `${geoData.city}, ${geoData.country_name}`;
      } else {
        location = token.ipAddress; 
      }
    } catch (error) {
      console.error('Error fetching geo location for IP:', token.ipAddress, error);
      location = token.ipAddress; 
    }
  }

    const parser = new UAParser(token.device); 
    const browser = parser.getBrowser();
    const os = parser.getOS();
    const device = parser.getDevice(); 
    console.log(`User found with lastActive: ${token.lastActive}`);
 
    const browserName = browser.name || 'Nepoznat Browser';
    const browserVersion = browser.version ? ` (${browser.version.split('.')[0]})` : ''; 
    const browserInfo = `${browserName}${browserVersion}`;

    const osName = os.name || 'Nepoznat OS';
    const osVersion = os.version ? ` ${os.version}` : '';
    const osInfo = `${osName}${osVersion}`;

    let deviceType = 'Desktop';
    if (device.type === 'mobile') {
        deviceType = 'Mobile';
    } else if (device.type === 'tablet') {
        deviceType = 'Tablet';
    } else if (device.type) { 
        deviceType = device.type.charAt(0).toUpperCase() + device.type.slice(1);
    }


    const displayLocation = location;
    const displayDevice = `${osInfo} - ${browserInfo}`; 

    return {
      token: token.token,
      email: this.email || '',
      fullUserAgent: token.device,
      ipAddress: token.ipAddress,
      lastActive: token.lastActive,
      current: curr,
      browser: browserName, 
      os: osName,        
      deviceType: deviceType,
      displayLocation: displayLocation,
      displayDevice: displayDevice
    };
  }

  
  private formatLocation(ipAddress: string): string {
    return ipAddress || 'Unknown Location';
  }
/*
  revokeToken(id: string) {
    console.log(`Revoking token ${id}`);
    this.displaySessions = this.displaySessions.filter(s => s.token !== id);
  }

  logoutAll() {
    console.log('Logging out of all other tokens');
    this.displaySessions = this.displaySessions.filter(s => s.current);
  }*/

      revokeToken(token: string) {
    console.log(`Revoking token ${token} via backend API.`);
    this.tokenService.revokeSpecificSession(token).subscribe({
      next: () => {
        console.log(`Session successfully revoked on backend.`);
        this.displaySessions = this.displaySessions.filter(s => s.token !== token);

      },
      error: (err) => {
        console.error(`Failed to revoke session`, err);
      }
    });
  }


  logoutAll() {
    console.log(`Logging out of all other tokens for ${this.email} via backend API.`);
    this.tokenService.revokeAllOtherSessions(this.email).subscribe({
      next: () => {
        console.log(`Successfully revoked all other sessions for ${this.email} on backend.`);

        this.displaySessions = this.displaySessions.filter(s => s.current);

      },
      error: (err) => {
        console.error('Failed to revoke all other sessions', err);
      }
    });
  }
}