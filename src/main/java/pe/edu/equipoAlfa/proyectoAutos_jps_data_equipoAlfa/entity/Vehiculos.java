package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;


import java.util.Date;
import java.util.List;


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Vehiculos {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idVehi;
    private String nombre;
    private String detalles;
    private Boolean activo;
    private Date fecha_lanzamiento;
    private Integer stock;
    private Double precio;

    @ToString.Exclude
    @ManyToOne
    @JoinColumn(name = "id_cat")
    private CatVehiculos cat_vehiculos;

    //para carrito
    @ToString.Exclude
    @OneToMany(mappedBy = "vehiculo")
    private List<CarritoCompras> carrito;


    @Temporal(TemporalType.TIMESTAMP)
    private Date lastUpdate;
    @PrePersist
    protected void onCreate() { lastUpdate = new Date(); }

}
