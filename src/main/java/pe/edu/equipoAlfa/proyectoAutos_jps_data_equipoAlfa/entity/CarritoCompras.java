package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;

@Entity
@Table(name = "carrito_compras")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CarritoCompras {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idCarrito;
    private Integer cantidad;
    private String direccionEntrega;
    private Double montoTotal;



    @ManyToOne
    @JoinColumn(name = "id_vehi")
    private Vehiculos vehiculo;

    @ManyToOne
    @JoinColumn(name = "id_usuario")
    private Clientes cliente;


    @Temporal(TemporalType.TIMESTAMP)
    private Date lastUpdate;
    @PrePersist
    protected void onCreate() { lastUpdate = new Date(); }

}
