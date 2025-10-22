import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'parseDn'
})
export class ParseDnPipe implements PipeTransform {

  /**
   * Pretvara dugačak X.500 DN string u formatiran objekat ili string.
   * Primer ulaza: "CN=Pera Peric,OU=IT,O=Moja Firma,C=RS"
   * @param value Dugačak DN string.
   * @returns Formatirani string.
   */
  transform(value: string | undefined | null): string {
    if (!value) {
      return 'N/A';
    }

    const parts = value.split(',');
    const dnObject: { [key: string]: string } = {};

    parts.forEach(part => {
      const keyValue = part.split('=');
      if (keyValue.length === 2) {
        const key = keyValue[0].trim().toUpperCase();
        const val = keyValue[1].trim();
        dnObject[key] = val;
      }
    });

    // Kreiramo formatirani string. Možete ga prilagoditi kako želite.
    // Primer 1: Samo CN
    // return dnObject['CN'] || 'Unknown';

    // Primer 2: CN, O
    const cn = dnObject['CN'] || '';
    const o = dnObject['O'] || '';
    
    // Ako oba postoje, spoji ih. Ako postoji samo jedan, prikaži samo njega.
    return [cn, o].filter(Boolean).join(', ');
  }
}