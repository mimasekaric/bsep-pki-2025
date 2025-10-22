import { Component, OnInit, ViewChild, ElementRef, AfterViewInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-splash-screen',
  templateUrl: './splash-screen.component.html',
  styleUrls: ['./splash-screen.component.css']
})
export class SplashScreenComponent implements OnInit, AfterViewInit {
  @ViewChild('splashVideo', { static: false }) videoElement!: ElementRef<HTMLVideoElement>;
  
  videoLoaded = false;
  showPlayButton = false;
  videoError = false;

  constructor(private router: Router) { }

  ngOnInit(): void {
    // Skraći fallback timeout na 15 sekundi
    setTimeout(() => {
      if (!this.videoLoaded) {
        this.skipSplash();
      }
    }, 15000);

    // Dodaj click listener na ceo dokument za autoplay trigger
    document.addEventListener('click', this.triggerAutoplay.bind(this), { once: true });
    document.addEventListener('touchstart', this.triggerAutoplay.bind(this), { once: true });
  }

  private triggerAutoplay(): void {
    if (this.videoElement && this.videoElement.nativeElement) {
      this.attemptAutoplay();
    }
  }

  ngAfterViewInit(): void {
    this.initializeVideo();
    // Agresivno pokušavanje reprodukcije
    this.forceVideoPlay();
  }

  initializeVideo(): void {
    const video = this.videoElement.nativeElement;
    
    // Postavi video atribute za maksimalnu kompatibilnost
    video.muted = true;
    video.playsInline = true;
    video.autoplay = true;
    video.defaultMuted = true;
    
    // Add event listeners
    video.addEventListener('loadeddata', () => {
      this.videoLoaded = true;
      this.attemptAutoplay();
    });

    video.addEventListener('loadedmetadata', () => {
      this.attemptAutoplay();
    });

    video.addEventListener('canplay', () => {
      this.attemptAutoplay();
    });

    video.addEventListener('canplaythrough', () => {
      this.attemptAutoplay();
    });

    video.addEventListener('error', () => {
      this.videoError = true;
      // Čak i ako je greška, pokušaj da učitaš ponovo
      setTimeout(() => {
        this.retryVideoLoad();
      }, 1000);
    });

    // Dodaj event listenere za instant završetak videa
    video.addEventListener('ended', () => {
      console.log('Video ended event triggered');
      this.onVideoEnded();
    });

    // Dodatni listeneri za sigurnost
    video.addEventListener('pause', () => {
      // Ako je video pauziran blizu kraja, možda je završen
      if (video.currentTime >= video.duration - 0.1) {
        console.log('Video near end and paused - triggering end');
        this.onVideoEnded();
      }
    });

    video.addEventListener('timeupdate', () => {
      // Proveri da li je video blizu kraja
      if (video.currentTime >= video.duration - 0.1 && video.duration > 0) {
        console.log('Video reached end via timeupdate');
        this.onVideoEnded();
      }
    });

    // Forsiraj load odmah
    video.load();
  }

  private forceVideoPlay(): void {
    // Pokušaj reprodukciju u intervalima
    const playInterval = setInterval(async () => {
      if (this.videoElement && this.videoElement.nativeElement) {
        const video = this.videoElement.nativeElement;
        
        if (video.readyState >= 3) { // HAVE_FUTURE_DATA
          try {
            await video.play();
            this.showPlayButton = false;
            clearInterval(playInterval);
          } catch (error) {
            // Nastavi da pokušava
            console.log('Pokušavam ponovo autoplay...');
          }
        }
      }
    }, 500);

    // Zaustavi pokušaje nakon 10 sekundi
    setTimeout(() => {
      clearInterval(playInterval);
    }, 10000);
  }

  private retryVideoLoad(): void {
    const video = this.videoElement.nativeElement;
    video.load();
    setTimeout(() => {
      this.attemptAutoplay();
    }, 500);
  }

  async attemptAutoplay(): Promise<void> {
    const video = this.videoElement.nativeElement;
    
    try {
      // Uvek postavi muted pre reprodukcije
      video.muted = true;
      video.volume = 0;
      
      // Pokušaj reprodukciju
      const playPromise = video.play();
      
      if (playPromise !== undefined) {
        await playPromise;
        console.log('Video se uspešno reprodukuje!');
        this.showPlayButton = false;
      }
    } catch (error) {
      console.log('Autoplay neuspešan, pokušavam ponovo...', error);
      
      // Pokušaj ponovo nakon kratke pauze
      setTimeout(async () => {
        try {
          video.currentTime = 0;
          await video.play();
          this.showPlayButton = false;
        } catch (retryError) {
          console.log('Drugi pokušaj neuspešan');
          // Ne prikazuj play dugme, nastavi da pokušava u pozadini
        }
      }, 1000);
    }
  }

  async onPlayButtonClick(): Promise<void> {
    const video = this.videoElement.nativeElement;
    
    try {
      await video.play();
      this.showPlayButton = false;
    } catch (error) {
      console.error('Manual play failed:', error);
      this.skipSplash();
    }
  }

  onVideoEnded(): void {
    // Instant prelazak na login kada se video završi
    console.log('Video završen - prelazim na login');
    this.router.navigate(['/login']).then(() => {
      console.log('Uspešno preusmeren na login');
    });
  }

  onTimeUpdate(event: any): void {
    const video = event.target;
    // Dupla provera kroz Angular event binding
    if (video.currentTime >= video.duration - 0.1 && video.duration > 0) {
      console.log('Video reached end via Angular timeupdate binding');
      this.onVideoEnded();
    }
  }

  onVideoLoaded(): void {
    this.videoLoaded = true;
  }

  skipSplash(): void {
    // Allow users to skip the splash screen
    this.router.navigate(['/login']);
  }
}