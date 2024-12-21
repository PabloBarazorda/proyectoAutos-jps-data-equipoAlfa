package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;


import java.util.List;

@Entity
@Data
@Table(name = "catvehiculos")
@NoArgsConstructor
@AllArgsConstructor
public class CatVehiculos {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id_cat;
    private String Marca;
    private Boolean activo;
    private String Tipo;
    private String Descripcion;


    @ToString.Exclude
    @OneToMany(mappedBy = "cat_vehiculos", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Vehiculos> vehiculos;




    public Integer getId_cat() {
        return id_cat;
    }

    public String getMarca() {
        return Marca;
    }

    public Boolean getActivo() {
        return activo;
    }

    public String getTipo() {
        return Tipo;
    }

    public String getDescripcion() {
        return Descripcion;
    }

    public List<Vehiculos> getVehiculos() {
        return vehiculos;
    }
}
