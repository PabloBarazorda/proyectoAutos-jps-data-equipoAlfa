package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service;

import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosDetallesDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosEditarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosRegistrarDto;

import java.util.List;

public interface MaintenanceCatVehiService {
    /*-------CatVehiculos-----------*/
    List<CatVehiculosListarDto> getAllCatVehiculos();
    void registarCatVehi(CatVehiculosRegistrarDto catVehiculosRegistrarDto);

    CatVehiculosEditarDto getCatVehiculosEditarDto(int id);
    public void actualizarCatVehi(int id, CatVehiculosEditarDto catVehiculosEditarDto);
    /*Boolean actualizarCatVehi(CatVehiculosEditarDto catVehiculosEditarDto);*/
    Boolean eliminarCatVehi(Integer id) throws Exception;
    CatVehiculosDetallesDto getCatVehiculoDetalleById(Integer id_cat);
}
