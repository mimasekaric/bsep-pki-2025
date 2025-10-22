import { Component, EventEmitter, Input, Output } from '@angular/core';
import { TemplateInfoDTO } from '../../services/template.service';

@Component({
  selector: 'app-template-selection-modal',
  templateUrl: './template-selection-modal.component.html',
  styleUrls: ['./template-selection-modal.component.css']
})
export class TemplateSelectionModalComponent {

  // Ulazni podatak: niz šablona koje dobija od roditeljske komponente
  @Input() templates: TemplateInfoDTO[] = [];

  // Izlazni događaj: emituje izabrani šablon
  @Output() selected = new EventEmitter<TemplateInfoDTO>();

  // Izlazni događaj: emituje se kada treba zatvoriti modal
  @Output() close = new EventEmitter<void>();

  constructor() { }

  /**
   * Poziva se kada korisnik klikne na dugme "Izaberi".
   * Emituje izabrani šablon ka roditeljskoj komponenti.
   * @param template Izabrani šablon
   */
  selectTemplate(template: TemplateInfoDTO): void {
    this.selected.emit(template);
  }
}